from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, Text
from database import Base
from sqlalchemy.orm import relationship
from datetime import datetime

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    environment = Column(String, nullable=False)

    vulnerabilities = relationship(
    "Vulnerability",
    back_populates="asset"
)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    cve_id = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)
    description = Column(String, nullable=True)
    remediation = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    cvss_score = Column(Float, nullable=True)
    status = Column(String, nullable=False, default="open")
    discovered_at = Column(DateTime, default=datetime.utcnow)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)

    asset = relationship(
    "Asset",
    back_populates="vulnerabilities"
)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False, default="viewer")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    scanner = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)

    status = Column(String, nullable=False, default="pending")

    target = Column(String, nullable=False)
    raw_output = Column(Text, nullable=True)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    asset_id = Column(
        Integer,
        ForeignKey("assets.id"),
        nullable=False
    )

    asset = relationship("Asset")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=False
)
    asset_id = Column(
        Integer,
        ForeignKey("assets.id"),
        nullable=False
)
    title = Column(String, nullable=False)
    cve_id = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)
    template_id = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    cvss_score = Column(Float, nullable=True)
    protocol = Column(String, nullable=True)
    target = Column(String, nullable=False)
    description = Column(String, nullable=True)
    evidence = Column(String, nullable=True)
    status = Column(String, nullable=False, default="open")
    discovered_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan")
    asset = relationship("Asset")


class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, index=True)

    asset_id = Column(
        Integer,
        ForeignKey("assets.id"),
        nullable=False
    )

    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=False
    )

    port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)

    service_name = Column(String, nullable=True)
    product = Column(String, nullable=True)
    version = Column(String, nullable=True)

    discovered_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("Asset")
    scan = relationship("Scan")