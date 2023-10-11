from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class ComponentType(str, Enum):
    """Enum used to store the component types that can be used in the HealthCheckComponentStatus class."""

    DATASTORE = "datastore"
    INTERNAL = "internal"
    FULLNODE = "fullnode"


class HealthCheckStatus(str, Enum):
    """Enum used to store the component status that can be used in the HealthCheckComponentStatus class."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class ComponentHealthCheck:
    """This class is used to store the result of a health check in a specific component."""

    component_name: str
    component_type: ComponentType
    status: HealthCheckStatus
    output: str
    time: Optional[str] = None
    component_id: Optional[str] = None
    observed_value: Optional[str] = None
    observed_unit: Optional[str] = None

    def __post_init__(self) -> None:
        self.time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_json(self) -> dict[str, str]:
        """Return a dict representation of the object. All field names are converted to camel case."""
        json = {
            "componentType": self.component_type.value,
            "status": self.status.value,
            "output": self.output,
        }

        if self.time:
            json["time"] = self.time

        if self.component_id:
            json["componentId"] = self.component_id

        if self.observed_value:
            assert (
                self.observed_unit is not None
            ), "observed_unit must be set if observed_value is set"

            json["observedValue"] = self.observed_value
            json["observedUnit"] = self.observed_unit

        return json


@dataclass
class ServiceHealthCheck:
    """This class is used to store the result of a service health check."""

    description: str
    checks: dict[str, list[ComponentHealthCheck]]

    @property
    def status(self) -> HealthCheckStatus:
        "Return the status of the health check based on the status of the components."
        status = HealthCheckStatus.PASS

        for component_checks in self.checks.values():
            for check in component_checks:
                if check.status == HealthCheckStatus.FAIL:
                    return HealthCheckStatus.FAIL
                elif check.status == HealthCheckStatus.WARN:
                    status = HealthCheckStatus.WARN

        return status

    def __post_init__(self) -> None:
        """Perform some validations after the object is initialized."""
        # Make sure the checks dict is not empty
        if not self.checks:
            raise ValueError("checks dict cannot be empty")

    def get_http_status_code(self) -> int:
        """Return the HTTP status code for the status."""
        if self.status in [HealthCheckStatus.PASS]:
            return 200
        elif self.status in [HealthCheckStatus.WARN, HealthCheckStatus.FAIL]:
            return 503
        else:
            raise ValueError(f"Missing treatment for status {self.status}")

    def to_json(self) -> dict[str, Any]:
        """Return a dict representation of the object. All field names are converted to camel case."""
        return {
            "status": self.status.value,
            "description": self.description,
            "checks": {k: [c.to_json() for c in v] for k, v in self.checks.items()},
        }


class ComponentHealthCheckInterface(ABC):
    """This is an interface to be used by other classes implementing health checks for components."""

    @abstractmethod
    async def get_health_check(self) -> ComponentHealthCheck:
        """Return the health check status for the component."""
        raise NotImplementedError()
