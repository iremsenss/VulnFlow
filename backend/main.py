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
    current_user: models.User = Depends(get_current_user)
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
        401: {"description": "Not authenticated"}
    }
)
def get_vulnerabilities(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)

):
    vulnerabilities = db.query(models.Vulnerability).all()

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
        404: {"description": "Vulnerability not found"}
    }
)
def delete_vulnerability(
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
        409: {"description": "Asset with this value already exists"}
    }
)
def create_asset(
    asset: schemas.AssetCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
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
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    db_assets = db.query(models.Asset).all()

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
        404: {"description": "Asset not found"}
    }
)
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
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
        404: {"description": "Asset not found"}
    }
)
def update_asset(
    asset_id: int,
    updated_asset: schemas.AssetUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
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
        hashed_password=hashed_password
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
        "email": current_user.email
    }