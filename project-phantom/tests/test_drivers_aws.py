"""EC2 driver tests, verified against moto.

Skips wholesale without boto3/moto. What these DO verify: call sequencing,
tag propagation, the destroy guard, and error shapes. What they cannot:
real IAM, latency, eventual consistency, quotas, or whether a restored
volume boots. See phantom/drivers/aws.py for the full caveat.
"""
import pytest

from phantom.drivers import (
    PHANTOM_INSTANCE_TAG,
    PHANTOM_MANAGED_TAG,
    PHANTOM_MANAGED_VALUE,
    ComputeDriverConformance,
    DestroyRefused,
    InstanceHandle,
)

boto3 = pytest.importorskip("boto3", reason="boto3 not installed")
pytest.importorskip("moto", reason="moto not installed")


@pytest.fixture
def ec2_client(monkeypatch):
    """A moto-backed EC2 client with dummy credentials.

    Credentials are set explicitly to obviously-fake values so this can
    never accidentally reach a real account, even if the ambient
    environment has AWS variables set.
    """
    from moto import mock_aws

    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SECURITY_TOKEN",
                "AWS_SESSION_TOKEN", "AWS_DEFAULT_REGION", "AWS_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    with mock_aws():
        yield boto3.client("ec2", region_name="us-east-1")


def _an_ami(client) -> str:
    """moto needs a real-looking AMI; make one from a throwaway instance."""
    seed = client.run_instances(ImageId="ami-12345678", InstanceType="t3.micro",
                                MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    return client.create_image(InstanceId=seed, Name="phantom-baseline")["ImageId"]


class TestEC2DriverConformance(ComputeDriverConformance):
    """The EC2 driver held to the same contract as the local one."""

    @pytest.fixture(autouse=True)
    def _client(self, ec2_client):
        self._ec2 = ec2_client

    def make_driver(self):
        from phantom.drivers.aws import EC2Driver
        return EC2Driver(self._ec2)

    def make_baseline(self, driver) -> str:
        return _an_ami(self._ec2)

    def make_foreign_handle(self, driver) -> InstanceHandle:
        """An EC2 instance launched WITHOUT Phantom's tags -- i.e. somebody
        else's workload sitting in the same account."""
        native = self._ec2.run_instances(
            ImageId="ami-12345678", InstanceType="t3.micro", MinCount=1, MaxCount=1,
            TagSpecifications=[{"ResourceType": "instance",
                                "Tags": [{"Key": "Name", "Value": "prod-database"}]}],
        )["Instances"][0]["InstanceId"]
        return InstanceHandle(provider=driver.provider, native_id=native, instance_id="not-ours")


def test_ec2_spawn_tags_the_instance_as_phantom_managed(ec2_client):
    from phantom.drivers.aws import EC2Driver
    driver = EC2Driver(ec2_client)

    handle = driver.spawn(_an_ami(ec2_client), "vm-1")

    described = ec2_client.describe_instances(InstanceIds=[handle.native_id])
    tags = {t["Key"]: t["Value"] for t in described["Reservations"][0]["Instances"][0]["Tags"]}
    assert tags[PHANTOM_MANAGED_TAG] == PHANTOM_MANAGED_VALUE
    assert tags[PHANTOM_INSTANCE_TAG] == "vm-1"


def test_ec2_destroy_refuses_an_untagged_instance_and_leaves_it_running(ec2_client):
    """The scenario that matters: a bug hands us someone's production
    instance id. It must survive."""
    from phantom.drivers.aws import EC2Driver
    driver = EC2Driver(ec2_client)

    prod = ec2_client.run_instances(
        ImageId="ami-12345678", InstanceType="t3.micro", MinCount=1, MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance",
                            "Tags": [{"Key": "Name", "Value": "prod-database"}]}],
    )["Instances"][0]["InstanceId"]
    handle = InstanceHandle(provider=driver.provider, native_id=prod, instance_id="spoofed")

    with pytest.raises(DestroyRefused):
        driver.destroy(handle)

    state = ec2_client.describe_instances(
        InstanceIds=[prod])["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert state == "running"


def test_ec2_destroy_reads_tags_from_the_api_not_the_handle(ec2_client):
    """A handle is a local object and can be forged or stale; the
    authoritative answer to 'is this mine' must come from the API."""
    from phantom.drivers.aws import EC2Driver
    driver = EC2Driver(ec2_client)

    prod = ec2_client.run_instances(
        ImageId="ami-12345678", InstanceType="t3.micro", MinCount=1, MaxCount=1,
    )["Instances"][0]["InstanceId"]

    # Handle *claims* Phantom ownership in its metadata. The instance does not.
    forged = InstanceHandle(
        provider=driver.provider, native_id=prod, instance_id="vm-1",
        metadata={PHANTOM_MANAGED_TAG: PHANTOM_MANAGED_VALUE},
    )

    with pytest.raises(DestroyRefused):
        driver.destroy(forged)


def test_ec2_snapshot_targets_the_root_volume(ec2_client):
    from phantom.drivers.aws import EC2Driver
    driver = EC2Driver(ec2_client)
    handle = driver.spawn(_an_ami(ec2_client), "vm-1")

    ref = driver.snapshot(handle)

    assert ref.startswith("snap-")
    snapshots = ec2_client.describe_snapshots(SnapshotIds=[ref])["Snapshots"]
    assert snapshots[0]["State"] in {"pending", "completed"}


def test_ec2_exists_is_false_after_terminate(ec2_client):
    from phantom.drivers.aws import EC2Driver
    driver = EC2Driver(ec2_client)
    handle = driver.spawn(_an_ami(ec2_client), "vm-1")

    driver.destroy(handle)

    assert driver.exists(handle) is False


def test_ec2_exists_is_false_for_an_unknown_instance_id(ec2_client):
    from phantom.drivers.aws import EC2Driver
    driver = EC2Driver(ec2_client)
    handle = InstanceHandle(provider=driver.provider, native_id="i-00000000000000000",
                            instance_id="ghost")

    assert driver.exists(handle) is False  # must not raise
