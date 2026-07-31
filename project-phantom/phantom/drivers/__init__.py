"""Provider-agnostic compute drivers (see base.py for why this exists)."""

from phantom.drivers.base import (
    PHANTOM_INSTANCE_TAG,
    PHANTOM_MANAGED_TAG,
    PHANTOM_MANAGED_VALUE,
    ComputeDriver,
    ComputeDriverConformance,
    DestroyRefused,
    DriverError,
    InstanceHandle,
    InstanceNotFound,
)
from phantom.drivers.local import LocalDriver

__all__ = [
    "ComputeDriver",
    "ComputeDriverConformance",
    "DestroyRefused",
    "DriverError",
    "InstanceHandle",
    "InstanceNotFound",
    "LocalDriver",
    "PHANTOM_INSTANCE_TAG",
    "PHANTOM_MANAGED_TAG",
    "PHANTOM_MANAGED_VALUE",
]

# EC2Driver is intentionally NOT imported here: boto3 is an optional
# dependency and the local driver must work without it.
