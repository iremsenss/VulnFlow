from pydantic import BaseModel, Field
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