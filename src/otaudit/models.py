"""Data model of an engagement: what was authorised, what was seen, what was found."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Protocol(StrEnum):
    MODBUS = "modbus"
    S7COMM = "s7comm"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SEVERITY_ORDER = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
    Severity.INFO: 3,
}


class Window(BaseModel):
    model_config = ConfigDict(frozen=True)

    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _ordered(self) -> Window:
        if self.end <= self.start:
            raise ValueError("window.end must be after window.start")
        return self

    def contains(self, moment: datetime) -> bool:
        return self.start <= moment <= self.end


class Scope(BaseModel):
    """Written authorisation, in machine-readable form.

    The tool refuses to produce a report without one. A capture is worthless as
    evidence if nobody can say who allowed it to be taken and over what range.
    """

    model_config = ConfigDict(frozen=True)

    engagement: str = Field(min_length=1)
    authorized_by: str = Field(min_length=1)
    reference: str = Field(min_length=1)
    window: Window
    targets: list[IPv4Network] = Field(min_length=1)
    exclusions: list[IPv4Network] = Field(default_factory=list)
    notes: str | None = None

    def covers(self, address: IPv4Address) -> bool:
        if any(address in network for network in self.exclusions):
            return False
        return any(address in network for network in self.targets)

    def excluded(self, address: IPv4Address) -> bool:
        return any(address in network for network in self.exclusions)


class Device(BaseModel):
    address: IPv4Address
    roles: list[str] = Field(default_factory=list)
    protocols: list[Protocol] = Field(default_factory=list)
    unit_ids: list[int] = Field(default_factory=list)
    identification: dict[str, str] = Field(default_factory=dict)
    in_scope: bool = True
    excluded: bool = False
    other_ports: list[int] = Field(default_factory=list)


class Conversation(BaseModel):
    client: IPv4Address
    server: IPv4Address
    port: int
    protocol: Protocol
    requests: int = 0
    responses: int = 0
    writes: int = 0
    controls: int = 0
    unit_ids: list[int] = Field(default_factory=list)
    functions: dict[str, int] = Field(default_factory=dict)
    exceptions: dict[str, int] = Field(default_factory=dict)
    first_seen: datetime
    last_seen: datetime
    mean_interval_ms: float | None = None
    jitter_ms: float | None = None

    @property
    def exception_count(self) -> int:
        return sum(self.exceptions.values())

    @property
    def exception_ratio(self) -> float:
        return self.exception_count / self.responses if self.responses else 0.0


class Finding(BaseModel):
    identifier: str
    title: str
    severity: Severity
    assets: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    iec_62443: list[str] = Field(default_factory=list)
    anssi: list[str] = Field(default_factory=list)
    recommendation: str


class Capture(BaseModel):
    path: str
    started_at: datetime | None = None
    ended_at: datetime | None = None
    packets: int = 0
    industrial_frames: int = 0
    truncated_records: int = 0
    stream_gaps: int = 0
    within_window: bool = True


class Report(BaseModel):
    scope: Scope
    capture: Capture
    devices: list[Device] = Field(default_factory=list)
    conversations: list[Conversation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    generated_at: datetime

    @property
    def out_of_scope_devices(self) -> list[Device]:
        return [device for device in self.devices if not device.in_scope]
