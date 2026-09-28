from pydantic import BaseModel, Field, computed_field
from typing import Literal, Optional
from datetime import datetime

class Asset(BaseModel):
    name: str
    type: str   
    value: str
    environment: str

class AssetCreate(Asset):
    pass

class AssetResponse(Asset):
    id: int


class AssetUpdate(Asset):
    pass


class AssetListResponse(BaseModel):
    assets: list[AssetResponse]

class AssetDetailResponse(BaseModel):
    asset: AssetResponse

class AssetUpdateResponse(BaseModel):
    message: str
    asset: AssetResponse

class AssetDeleteResponse(BaseModel):
    message: str

class VulnerabilityBase(BaseModel):
    title: str
    cve_id: str | None = Field(
    default=None,
    pattern=r"^CVE-\d{4}-\d{4,}$"
)
    cwe_id: str | None = Field(
    default=None,
    pattern=r"^CWE-\d+$"
)
    description: str | None = None
    remediation: str | None = None
    severity: Literal["critical", "high", "medium", "low"]
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    status: Literal["open", "in_progress", "resolved", "closed"] = "open"
    asset_id: int

class VulnerabilityCreate(VulnerabilityBase):
    pass

class VulnerabilityResponse(VulnerabilityBase):
    id: int
    discovered_at: datetime

class VulnerabilityListResponse(BaseModel):
    vulnerabilities: list[VulnerabilityResponse]

class AssetCreateResponse(BaseModel):
    message: str
    asset: AssetResponse


class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str

class UserRoleUpdate(BaseModel):
    role: Literal["admin", "analyst", "viewer"]



class ScanCreate(BaseModel):
    scanner: Literal["nmap", "nuclei"]
    scan_type: str
    target: str
    asset_id: int


class ScanResponse(BaseModel):
    id: int
    scanner: str
    scan_type: str
    status: str
    target: str
    raw_output: str | None = None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    asset_id: int


class ScanOutputImport(BaseModel):
    raw_output: str

class ScanStatusUpdate(BaseModel):
    status: Literal["pending", "running", "completed", "failed"]

class FindingAssignmentUpdate(BaseModel):
    assigned_to: int | None = None  

class FindingResponse(BaseModel):
    id: int
    scan_id: int
    asset_id: int
    title: str
    cve_id: str | None = None
    cwe_id: str | None = None
    template_id: str | None = None
    severity: str
    cvss_score: float | None = None
    risk_score: float | None = None
    protocol: str | None = None
    target: str
    description: str | None = None
    evidence: str | None = None
    remediation: str | None = None
    remediation_updated_at: datetime | None = None
    retest_status: str
    retest_requested_at: datetime | None = None
    retest_completed_at: datetime | None = None
    retest_note: str | None = None

    status: str
    discovered_at: datetime
    assigned_to: int | None = None  # Include the assigned_to field

    @computed_field
    @property
    def risk_level(self) -> str | None:
        if self.risk_score is None:
            return None

        if self.risk_score >= 9.0:
            return "critical"
        elif self.risk_score >= 7.0:
            return "high"
        elif self.risk_score >= 4.0:
            return "medium"
        elif self.risk_score > 0:
            return "low"

        return "informational"


class FindingStatusUpdate(BaseModel):
    status: Literal["open", "in_progress", "resolved", "closed"]


class FindingRemediationUpdate(BaseModel):
    remediation: str | None = None


class FindingRetestResultUpdate(BaseModel):
    status: Literal["passed", "failed"]
    note: str | None = None


class ServiceResponse(BaseModel):
    id: int
    asset_id: int
    scan_id: int
    port: int
    protocol: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    hostname: str | None = None
    discovered_at: datetime