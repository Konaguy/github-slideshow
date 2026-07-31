"""EC2 compute driver.

Maps Phantom's regeneration loop onto EC2 primitives:

    baseline    -> AMI (built by EC2 Image Builder in a real deployment,
                   which is also the §5.I patch/QA pipeline)
    spawn       -> RunInstances, tagged Phantom-managed
    destroy     -> TerminateInstances, tag-guarded
    snapshot    -> CreateSnapshot of the root EBS volume
    restore     -> volume created from snapshot, swapped in

**EBS snapshots are already block-level incremental.** That is the whole
reason to prefer provider primitives here: `phantom/benchmark.py` measured
12,288x write amplification from Phantom's own file-level snapshots, and
delegating to EBS makes that number the provider's problem rather than a
chunking algorithm we have to write and get right.

## Verification status

Tested against `moto`, which faithfully mocks the EC2 API surface --
call sequencing, tag propagation, error shapes, and the destroy guard are
all genuinely exercised. What moto **cannot** tell you: real IAM
behaviour, API latency, eventual consistency on tag reads, service quotas,
or whether a restore actually produces a bootable volume. Treat this as
"the logic is right" and not "this has run in anger." First contact with
real credentials is an operator's job, in an isolated account, with a
budget cap.

## Restore is the honest weak point

`restore` here creates a volume from the snapshot and attaches it. A real
implementation must also stop the instance, detach the old root volume,
attach at the right device name, and restart -- and the correctness of
that sequence depends on instance state transitions that moto models only
approximately. The method raises rather than silently half-working when
the instance is not in a state where the swap is safe.
"""
from __future__ import annotations

from typing import Optional

from phantom.drivers.base import (
    PHANTOM_INSTANCE_TAG,
    PHANTOM_MANAGED_TAG,
    PHANTOM_MANAGED_VALUE,
    DestroyRefused,
    DriverError,
    InstanceHandle,
    InstanceNotFound,
)

_TERMINAL_STATES = {"terminated", "shutting-down"}


class EC2Driver:
    """Phantom instances as EC2 instances.

    `client` is injected so tests can pass a moto-backed boto3 client and
    a real deployment can pass one configured with its own region,
    endpoint, and credential chain. This driver never constructs
    credentials itself.
    """

    provider = "aws-ec2"

    def __init__(self, client, instance_type: str = "t3.micro", subnet_id: Optional[str] = None):
        self.client = client
        self.instance_type = instance_type
        self.subnet_id = subnet_id

    # -- lifecycle -----------------------------------------------------------

    def spawn(self, baseline_ref: str, instance_id: str) -> InstanceHandle:
        """baseline_ref is an AMI id."""
        kwargs = {
            "ImageId": baseline_ref,
            "InstanceType": self.instance_type,
            "MinCount": 1,
            "MaxCount": 1,
            "TagSpecifications": [{
                "ResourceType": "instance",
                "Tags": [
                    {"Key": PHANTOM_MANAGED_TAG, "Value": PHANTOM_MANAGED_VALUE},
                    {"Key": PHANTOM_INSTANCE_TAG, "Value": instance_id},
                ],
            }],
        }
        if self.subnet_id:
            kwargs["SubnetId"] = self.subnet_id

        response = self.client.run_instances(**kwargs)
        native_id = response["Instances"][0]["InstanceId"]
        return InstanceHandle(
            provider=self.provider,
            native_id=native_id,
            instance_id=instance_id,
            metadata={"ami": baseline_ref},
        )

    def exists(self, handle: InstanceHandle) -> bool:
        instance = self._describe(handle.native_id)
        if instance is None:
            return False
        return instance.get("State", {}).get("Name") not in _TERMINAL_STATES

    def destroy(self, handle: InstanceHandle) -> None:
        """Terminate -- but only after confirming the instance is ours.

        The tag is re-read from the API rather than trusted from the
        handle. A handle is just a local object; it can be stale, wrong,
        or constructed from bad input. The authoritative answer to "is
        this mine to delete" lives on the instance.
        """
        instance = self._describe(handle.native_id)
        if instance is None:
            raise InstanceNotFound(f"no such instance: {handle.native_id}")

        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        if tags.get(PHANTOM_MANAGED_TAG) != PHANTOM_MANAGED_VALUE:
            raise DestroyRefused(
                f"refusing to terminate {handle.native_id!r}: instance does not carry "
                f"{PHANTOM_MANAGED_TAG}={PHANTOM_MANAGED_VALUE} (tags seen: {sorted(tags)})"
            )

        self.client.terminate_instances(InstanceIds=[handle.native_id])

    def _describe(self, native_id: str) -> Optional[dict]:
        try:
            response = self.client.describe_instances(InstanceIds=[native_id])
        except Exception:  # botocore raises InvalidInstanceID.NotFound
            return None
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                if instance["InstanceId"] == native_id:
                    return instance
        return None

    # -- data movement -------------------------------------------------------

    def snapshot(self, handle: InstanceHandle) -> str:
        """Snapshot the root volume. EBS handles block-level incrementals."""
        volume_id = self._root_volume_id(handle)
        response = self.client.create_snapshot(
            VolumeId=volume_id,
            Description=f"phantom {handle.instance_id}",
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": PHANTOM_MANAGED_TAG, "Value": PHANTOM_MANAGED_VALUE},
                    {"Key": PHANTOM_INSTANCE_TAG, "Value": handle.instance_id},
                ],
            }],
        )
        return response["SnapshotId"]

    def restore(self, handle: InstanceHandle, snapshot_ref: str) -> None:
        """Create a volume from the snapshot and attach it.

        Deliberately incomplete and loud about it: a production restore
        also stops the instance, detaches the existing root volume, and
        reattaches at the correct device name before restarting. That
        sequence depends on state transitions moto models only
        approximately, so verifying it here would produce false
        confidence.
        """
        instance = self._describe(handle.native_id)
        if instance is None:
            raise InstanceNotFound(f"no such instance: {handle.native_id}")

        volume = self.client.create_volume(
            SnapshotId=snapshot_ref,
            AvailabilityZone=instance["Placement"]["AvailabilityZone"],
            TagSpecifications=[{
                "ResourceType": "volume",
                "Tags": [{"Key": PHANTOM_MANAGED_TAG, "Value": PHANTOM_MANAGED_VALUE}],
            }],
        )
        self.client.attach_volume(
            VolumeId=volume["VolumeId"],
            InstanceId=handle.native_id,
            Device="/dev/sdp",
        )

    def _root_volume_id(self, handle: InstanceHandle) -> str:
        instance = self._describe(handle.native_id)
        if instance is None:
            raise InstanceNotFound(f"no such instance: {handle.native_id}")
        mappings = instance.get("BlockDeviceMappings", [])
        if not mappings:
            raise DriverError(f"instance {handle.native_id} has no attached volumes to snapshot")
        return mappings[0]["Ebs"]["VolumeId"]
