from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

import models
import schemas

from database import engine, SessionLocal
from sqlalchemy.orm import Session

import bcrypt

from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone

import os
from dotenv import load_dotenv

from typing import Literal

from sqlalchemy import func

from parsers import parse_nuclei_output, parse_nuclei_json, parse_nuclei_jsonl, parse_nmap_xml


SECRET_KEY = "vulnflow-super-secret-key-change-this"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


models.Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(data: dict):
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({"exp": expire})

    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        user_id = payload.get("sub")

        if user_id is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    user = db.query(models.User).filter(
        models.User.id == int(user_id)
    ).first()

    if user is None:
        raise credentials_exception

    return user


def require_role(allowed_roles: list[str]):
    def role_checker(
        current_user: models.User = Depends(get_current_user)
    ):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions"
            )

        return current_user

    return role_checker

app = FastAPI(
    title="VulnFlow API",
    description="Vulnerability Management Platform",
    version="0.1.0",
)


models.Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



app = FastAPI(
    title="VulnFlow API",
    description="Vulnerability Management Platform",
    version="0.1.0",
)


@app.get("/health")
def health():
    return {"status": "ok"}

@app.post(
    "/vulnerabilities",
    response_model=schemas.VulnerabilityResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        401: {"description": "Not authenticated"},
        404: {"description": "Asset not found"}
    }
)
def create_vulnerability(
    vulnerability: schemas.VulnerabilityCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        require_role(["admin", "analyst"])
)
):
    asset = db.query(models.Asset).filter(
        models.Asset.id == vulnerability.asset_id
    ).first()

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    db_vulnerability = models.Vulnerability(
        title=vulnerability.title,
        cve_id=vulnerability.cve_id,
        cwe_id=vulnerability.cwe_id,
        description=vulnerability.description,
        remediation=vulnerability.remediation,
        severity=vulnerability.severity,
        cvss_score=vulnerability.cvss_score,
        status=vulnerability.status,
        asset_id=vulnerability.asset_id
    )

    db.add(db_vulnerability)
    db.commit()
    db.refresh(db_vulnerability)

    return db_vulnerability

@app.get(
    "/vulnerabilities",
    response_model=schemas.VulnerabilityListResponse,
    responses={
        401: {"description": "Not authenticated"},
        402: {"description": "Unprocessable Entity"}
    }
)
def get_vulnerabilities(
    severity: Literal["critical", "high", "medium", "low"] | None = None,
    status: Literal["open", "in_progress", "resolved", "closed"] | None = None,
    asset_id: int | None = None,
    cve_id: str | None = None,
    cwe_id: str | None = None,
    search: str | None = None,
    min_cvss: float | None = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    query = db.query(models.Vulnerability)

    if severity:
        query = query.filter(
            models.Vulnerability.severity == severity
        )

    if status:
        query = query.filter(
            models.Vulnerability.status == status
        )   

    if asset_id:
        query = query.filter(
            models.Vulnerability.asset_id == asset_id
        )     

    if cve_id:
        query = query.filter(
            models.Vulnerability.cve_id == cve_id
        )    

    if cwe_id:
        query = query.filter(
            models.Vulnerability.cwe_id == cwe_id
        )

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            models.Vulnerability.title.ilike(search_pattern) |
            models.Vulnerability.description.ilike(search_pattern) |
            models.Vulnerability.remediation.ilike(search_pattern)
        )

    if min_cvss is not None:
        query = query.filter(
            models.Vulnerability.cvss_score >= min_cvss
        )
            

    vulnerabilities = query.all()

    return {"vulnerabilities": vulnerabilities}

@app.get(
    "/vulnerabilities/{vulnerability_id}",
    response_model=schemas.VulnerabilityResponse,
    responses={
        401: {"description": "Not authenticated"},
        404: {"description": "Vulnerability not found"}
    }
)
def get_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    vulnerability = db.query(models.Vulnerability).filter(
        models.Vulnerability.id == vulnerability_id
    ).first()

    if not vulnerability:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability not found"
        )

    return vulnerability

@app.put(
    "/vulnerabilities/{vulnerability_id}",
    response_model=schemas.VulnerabilityResponse,
    responses={
        401: {"description": "Not authenticated"},
        404: {"description": "Vulnerability or Asset not found"}
    }
)
def update_vulnerability(
    vulnerability_id: int,
    updated_vulnerability: schemas.VulnerabilityCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
    require_role(["admin", "analyst"])
)
):
    vulnerability = db.query(models.Vulnerability).filter(
        models.Vulnerability.id == vulnerability_id
    ).first()

    if not vulnerability:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability not found"
        )

    asset = db.query(models.Asset).filter(
        models.Asset.id == updated_vulnerability.asset_id
    ).first()

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    vulnerability.title = updated_vulnerability.title
    vulnerability.cve_id = updated_vulnerability.cve_id
    vulnerability.cwe_id = updated_vulnerability.cwe_id
    vulnerability.description = updated_vulnerability.description
    vulnerability.remediation = updated_vulnerability.remediation
    vulnerability.severity = updated_vulnerability.severity
    vulnerability.cvss_score = updated_vulnerability.cvss_score
    vulnerability.status = updated_vulnerability.status
    vulnerability.asset_id = updated_vulnerability.asset_id

    db.commit()
    db.refresh(vulnerability)

    return vulnerability

@app.delete(
    "/vulnerabilities/{vulnerability_id}",
    response_model=schemas.AssetDeleteResponse,
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Vulnerability not found"}
    }
)
def delete_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        require_role(["admin", "analyst"])
    )
):
    vulnerability = db.query(models.Vulnerability).filter(
        models.Vulnerability.id == vulnerability_id
    ).first()

    if not vulnerability:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability not found"
        )

    db.delete(vulnerability)
    db.commit()

    return {"message": "Vulnerability deleted successfully"}


@app.post(
    "/assets",
    response_model=schemas.AssetCreateResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "Asset created successfully"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        409: {"description": "Asset with this value already exists"}
    }
)
def create_asset(
    asset: schemas.AssetCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
    require_role(["admin", "analyst"])
)):
    existing_asset = db.query(models.Asset).filter(
        models.Asset.value == asset.value
    ).first()

    if existing_asset:
        raise HTTPException(
            status_code=409,
            detail="Asset with this value already exists"
        )

    db_asset = models.Asset(
        name=asset.name,
        type=asset.type,
        value=asset.value,
        environment=asset.environment
    )

    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)

    return {
        "message": "Asset created successfully",
        "asset": db_asset
    }




@app.get("/assets", 
         response_model= schemas.AssetListResponse,
         responses={
        401: {"description": "Not authenticated"}
    })
def get_assets(
    environment: str | None = None,
    type: str | None = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    query = db.query(models.Asset)

    if environment:
        query = query.filter(
            models.Asset.environment == environment
        )

    if type:
        query = query.filter(
        models.Asset.type == type
        )    
        
    db_assets = query.all()

    return {"assets": db_assets}



@app.get("/assets/{asset_id}", 
         response_model=schemas.AssetDetailResponse,
         responses={
             401: {"description": "Not authenticated"},
             404: {"description": "Asset not found"}
         })
def get_asset(asset_id: int, 
              db: Session = Depends(get_db),
              current_user: models.User = Depends(get_current_user)):
    db_asset = db.query(models.Asset).filter(
        models.Asset.id == asset_id
    ).first()

    if db_asset:
        return {"asset": db_asset}

    raise HTTPException(
        status_code=404,
        detail="Asset not found"
    )

@app.delete(
    "/assets/{asset_id}",
    response_model=schemas.AssetDeleteResponse,
    responses={
        400: {"description": "Asset has associated vulnerabilities"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Asset not found"}
    }
)
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        require_role(["admin", "analyst"])
    )
):
    db_asset = db.query(models.Asset).filter(
        models.Asset.id == asset_id
    ).first()

    if not db_asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    if db_asset.vulnerabilities:
        raise HTTPException(
            status_code=400,
            detail="Asset has associated vulnerabilities and cannot be deleted"
        )

    db.delete(db_asset)
    db.commit()

    return {"message": "Asset deleted successfully"}



@app.put(
    "/assets/{asset_id}",
    response_model=schemas.AssetUpdateResponse,
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Asset not found"}
    }
)
def update_asset(
    asset_id: int,
    updated_asset: schemas.AssetUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
    require_role(["admin", "analyst"])
    )):
    db_asset = db.query(models.Asset).filter(
        models.Asset.id == asset_id
    ).first()

    if db_asset:
        db_asset.name = updated_asset.name
        db_asset.type = updated_asset.type
        db_asset.value = updated_asset.value
        db_asset.environment = updated_asset.environment

        db.commit()
        db.refresh(db_asset)

        return {
            "message": "Asset updated successfully",
            "asset": db_asset
        }

    raise HTTPException(
        status_code=404,
        detail="Asset not found"
    )



@app.get(
    "/assets/{asset_id}/vulnerabilities",
    response_model=schemas.VulnerabilityListResponse,
    responses={
        401: {"description": "Not authenticated"},
        404: {"description": "Asset not found"}
    }
)
def get_asset_vulnerabilities(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    asset = db.query(models.Asset).filter(
        models.Asset.id == asset_id
    ).first()

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    return {"vulnerabilities": asset.vulnerabilities}


@app.post(
    "/register",
    response_model=schemas.UserResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {"description": "Username already exists"}
    }
)


@app.post(
    "/register",
    response_model=schemas.UserResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {"description": "Username or email already exists"}
    }
)
def register_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db)
):
    # Username kontrolü
    existing_user = db.query(models.User).filter(
        models.User.username == user.username
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Username already exists"
        )

    # Email kontrolü
    existing_email = db.query(models.User).filter(
        models.User.email == user.email
    ).first()

    if existing_email:
        raise HTTPException(
            status_code=409,
            detail="Email already exists"
        )

    # Şifreyi hashle
    hashed_password = bcrypt.hashpw(
        user.password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    # Kullanıcı oluştur
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role="viewer"
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


@app.post("/login",
        responses={
        401: {"description": "Invalid username or password"}
    })
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(
        models.User.username == form_data.username
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    password_valid = bcrypt.checkpw(
        form_data.password.encode("utf-8"),
        user.hashed_password.encode("utf-8")
    )

    if not password_valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    access_token = create_access_token(
    data={
        "sub": str(user.id),
        "username": user.username
    }
)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username
    }


@app.get("/me",
    responses={
        401: {"description": "Not authenticated"}
    }
)
def read_current_user(
    current_user: models.User = Depends(get_current_user)
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role
    }




@app.put(
    "/users/{user_id}/role",
    response_model=schemas.UserResponse,
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "User not found"}
    }
)
def update_user_role(
    user_id: int,
    role_update: schemas.UserRoleUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        require_role(["admin"])
    )
):
    user = db.query(models.User).filter(
        models.User.id == user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    user.role = role_update.role

    db.commit()
    db.refresh(user)

    return user




@app.get("/dashboard/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    total_assets = db.query(models.Asset).count()
    total_vulnerabilities = db.query(models.Vulnerability).count()

    critical_count = db.query(models.Vulnerability).filter(
        models.Vulnerability.severity == "critical"
    ).count()

    high_count = db.query(models.Vulnerability).filter(
        models.Vulnerability.severity == "high"
    ).count()

    medium_count = db.query(models.Vulnerability).filter(
    models.Vulnerability.severity == "medium"
).count()

    low_count = db.query(models.Vulnerability).filter(
    models.Vulnerability.severity == "low"
).count()

    open_count = db.query(models.Vulnerability).filter(
    models.Vulnerability.status == "open"
).count()

    in_progress_count = db.query(models.Vulnerability).filter(
    models.Vulnerability.status == "in_progress"
).count()

    resolved_count = db.query(models.Vulnerability).filter(
    models.Vulnerability.status == "resolved"
).count()

    closed_count = db.query(models.Vulnerability).filter(
    models.Vulnerability.status == "closed"
).count()

    average_cvss = db.query(
    func.avg(models.Vulnerability.cvss_score)
).scalar()

    return {
        "total_assets": total_assets,
        "total_vulnerabilities": total_vulnerabilities,
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "open": open_count,
        "resolved": resolved_count,
        "closed": closed_count,
        "in_progress": in_progress_count,
        
        "average_cvss": round(average_cvss, 2) if average_cvss is not None else 0,
    }


@app.post(
    "/scans",
    response_model=schemas.ScanResponse,
    status_code=status.HTTP_201_CREATED
)
def create_scan(
    scan: schemas.ScanCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        require_role(["admin", "analyst"])
    )
):
    asset = db.query(models.Asset).filter(
        models.Asset.id == scan.asset_id
    ).first()

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    db_scan = models.Scan(
        scanner=scan.scanner,
        scan_type=scan.scan_type,
        target=scan.target,
        asset_id=scan.asset_id,
        status="pending"
    )

    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    return db_scan


@app.get(
    "/scans",
    response_model=list[schemas.ScanResponse],
    responses={
        401: {"description": "Not authenticated"}
    }
)
def get_scans(
    status: Literal["pending", "running", "completed", "failed"] | None = None,
    scanner: Literal["nmap", "nuclei"] | None = None,
    asset_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    query = db.query(models.Scan)

    if status:
        query = query.filter(
            models.Scan.status == status
        )

    if scanner:
        query = query.filter(
            models.Scan.scanner == scanner
        )

    if asset_id:
        query = query.filter(
            models.Scan.asset_id == asset_id
        )

    return query.all()

@app.get(
    "/scans",
    response_model=list[schemas.ScanResponse],
    responses={
        401: {"description": "Not authenticated"}
    }
)
def get_scans(
    status: Literal["pending", "running", "completed", "failed"] | None = None,
    scanner: Literal["nmap", "nuclei"] | None = None,
    asset_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    query = db.query(models.Scan)

    if status:
        query = query.filter(models.Scan.status == status)

    if scanner:
        query = query.filter(models.Scan.scanner == scanner)

    if asset_id:
        query = query.filter(models.Scan.asset_id == asset_id)

    return query.all()


@app.patch(
    "/scans/{scan_id}/status",
    response_model=schemas.ScanResponse,
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Scan not found"}
    }
)
def update_scan_status(
    scan_id: int,
    status_update: schemas.ScanStatusUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        require_role(["admin", "analyst"])
    )
):
    scan = db.query(models.Scan).filter(
        models.Scan.id == scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    scan.status = status_update.status

    if status_update.status == "running" and scan.started_at is None:
        scan.started_at = datetime.now(timezone.utc)


    if status_update.status in ["completed", "failed"] and scan.completed_at is None:
        scan.completed_at = datetime.now(timezone.utc)
    
    db.commit()
    db.refresh(scan)

    return scan


@app.delete(
    "/scans/{scan_id}",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Scan not found"}
    }
)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        require_role(["admin", "analyst"])
    )
):
    scan = db.query(models.Scan).filter(
        models.Scan.id == scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    db.delete(scan)
    db.commit()

    return {
        "message": "Scan deleted successfully"
    }




@app.post(
    "/scans/{scan_id}/import",
    response_model=schemas.ScanResponse,
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Scan not found"}
    }
)
def import_scan_output(
    scan_id: int,
    output: schemas.ScanOutputImport,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        require_role(["admin", "analyst"])
    )
):
    scan = db.query(models.Scan).filter(
        models.Scan.id == scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    scan.raw_output = output.raw_output

    parsed_results = []

    if scan.scanner == "nuclei":
        parsed_results = parse_nuclei_jsonl(output.raw_output)

        if not parsed_results:
            parsed_result = parse_nuclei_output(output.raw_output)

            if parsed_result:
                parsed_results.append(parsed_result)

    if scan.scanner == "nmap":
        nmap_results = parse_nmap_xml(output.raw_output)

        if nmap_results is None:
            raise HTTPException(
                status_code=400,
                detail="Invalid Nmap XML output"
            )

    for host in nmap_results:
        for port in host["ports"]:

            existing_service = db.query(models.Service).filter(
                models.Service.scan_id == scan.id,
                models.Service.port == port["port"],
                models.Service.protocol == port["protocol"]
            ).first()

            if existing_service:
                continue

            service = models.Service(
                asset_id=scan.asset_id,
                scan_id=scan.id,
                port=port["port"],
                protocol=port["protocol"],
                service_name=port["service"],
                product=port["product"],
                version=port["version"]
            )

            db.add(service)

    for parsed_result in parsed_results:

        existing_finding = db.query(models.Finding).filter(
            models.Finding.scan_id == scan.id,
            models.Finding.template_id == parsed_result.get("template_id"),
            models.Finding.target == parsed_result.get("target")
        ).first()

        if not existing_finding:
            finding = models.Finding(
                scan_id=scan.id,
                asset_id=scan.asset_id,
                title=parsed_result.get("title")
                or parsed_result.get("cve_id")
                or "Unknown Finding",
                cve_id=parsed_result.get("cve_id"),
                cwe_id=parsed_result.get("cwe_id"),
                template_id=parsed_result.get("template_id"),
                severity=parsed_result.get("severity", "info"),
                cvss_score=parsed_result.get("cvss_score"),
                protocol=parsed_result.get("protocol"),
                target=parsed_result.get("target") or scan.target,
                evidence=parsed_result.get("evidence") or output.raw_output
            )


            db.add(finding)

    db.commit()
    db.refresh(scan)

    return scan




@app.get(
    "/findings",
    response_model=list[schemas.FindingResponse],
    responses={
        401: {"description": "Not authenticated"}
    }
)
def get_findings(
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None,
    status: Literal["open", "in_progress", "resolved", "closed"] | None = None,
    asset_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    query = db.query(models.Finding)

    if severity:
        query = query.filter(
            models.Finding.severity == severity
        )

    if status:
        query = query.filter(
            models.Finding.status == status
        )

    if asset_id:
        query = query.filter(
            models.Finding.asset_id == asset_id
        )

    return query.all()

@app.get(
    "/findings/{finding_id}",
    response_model=schemas.FindingResponse,
    responses={
        401: {"description": "Not authenticated"},
        404: {"description": "Finding not found"}
    }
)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    finding = db.query(models.Finding).filter(
        models.Finding.id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    return finding

@app.patch(
    "/findings/{finding_id}/status",
    response_model=schemas.FindingResponse,
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Finding not found"}
    }
)   
def update_finding_status(
    finding_id: int,
    status_update: schemas.FindingStatusUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(
        require_role(["admin", "analyst"])
    )
):
    finding = db.query(models.Finding).filter(
        models.Finding.id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    finding.status = status_update.status

    db.commit()
    db.refresh(finding)

    return finding


@app.get(
    "/services",
    response_model=list[schemas.ServiceResponse],
    responses={
        401: {"description": "Not authenticated"}
    }
)
def get_services(
    asset_id: int | None = None,
    scan_id: int | None = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    query = db.query(models.Service)

    if asset_id is not None:
        query = query.filter(
            models.Service.asset_id == asset_id
        )

    if scan_id is not None:
        query = query.filter(
            models.Service.scan_id == scan_id
        )

    return query.all()