"""
FastAPI Authentication Module
Handles password hashing (bcrypt), JWT generation, token decoding,
and Role-Based Access Control (RBAC) dependency injections.
"""

import os
import sys
from datetime import datetime, timedelta
from typing import List, Optional

# Path configuration for direct execution
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from src.config import settings
from src.database_manager import get_db_api, db_get_user_by_username, User
from src.utils.logger import get_auth_logger

auth_logger = get_auth_logger()

# Configure Passlib hashing context (specifically sha256_crypt)
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

# OAuth2 scheme definition
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

def hash_password(password: str) -> str:
    """Hashes a plain-text password using bcrypt."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against its hashed value."""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generates an encrypted JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db_api)) -> User:
    """
    Decodes the JWT token, extracts the username, and fetches the User from the database.
    Raises 401 Unauthorized if the token is invalid or expired.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials, token invalid or expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError as e:
        auth_logger.warning(f"Failed token validation attempt: {str(e)}")
        raise credentials_exception

    user = db_get_user_by_username(db, username)
    if user is None:
        raise credentials_exception
    return user

class RoleChecker:
    """Enforces Role-Based Access Control (RBAC) on FastAPI endpoints."""
    
    def __init__(self, allowed_roles: List[str]) -> None:
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: User = Depends(get_current_user)) -> User:
        """Verifies if the authenticated user's role is authorized to access the endpoint."""
        if current_user.role not in self.allowed_roles:
            auth_logger.warning(
                f"Unauthorized access block: User '{current_user.username}' (Role: {current_user.role}) "
                f"attempted to access an endpoint restricted to: {self.allowed_roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation restricted. Requires role in: {self.allowed_roles}. Current role: {current_user.role}."
            )
        return current_user
