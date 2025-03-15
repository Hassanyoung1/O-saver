from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.core.config import settings
from app.models.user import User
from app.schemas.user import TokenData
from sqlalchemy.orm import Session
from sqlalchemy import or_

class AuthService:
    """
    Authentication service for user registration, login, and token management.
    """
    
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    def hashed_password(cls, password: str) -> str:
        """
        Hashes the given password.
        
        Args:
            password (str): Plain text password.

        Returns:
            str: Hashed password.
        """
        return cls.pwd_context.hash(password)

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        """
        Verifies a plain password against a hashed password.
        
        Args:
            plain_password (str): Plain text password.
            hashed_password (str): Hashed password.

        Returns:
            bool: True if passwords match, False otherwise.
        """
        return cls.pwd_context.verify(plain_password, hashed_password)

    @classmethod
    def create_access_token(cls, user: User) -> str:
        """
        Generates a JWT access token.
        
        Args:
            user (User): The user for whom the token is generated.

        Returns:
            str: Encoded JWT token.
        """
        payload = {
            "user_id": user.id,
            "is_agent": user.is_agent,
            "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    @classmethod
    def decode_token(cls, token: str) -> Optional[TokenData]:
        """
        Decodes a JWT token.
        
        Args:
            token (str): The JWT token.

        Returns:
            TokenData: Extracted token data if valid, else None.
        """
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            return TokenData(user_id=payload["user_id"], is_agent=payload["is_agent"])
        except JWTError:
            return None
        

    @classmethod
    def login(cls, db: Session, phone: Optional[str], email: Optional[str], password: str):
        """
        Authenticates a user and returns a JWT token if valid.
        """
        if not phone and not email:
            return {"error": "Either phone or email must be provided"}, 400

        # Print debugging logs to verify query inputs
        print(f"🔍 Debug: Searching for user with phone='{phone}' OR email='{email}'")

        # Query the database
        user = db.query(User).filter(or_(User.phone == phone, User.email == email)).first()

        if not user:
            print(f"❌ Debug: User not found for phone='{phone}' OR email='{email}'")  # Debugging Log
            return {"error": "User not found"}, 404

        print(f"✅ Debug: User found: {user.name}, Phone: {user.phone}, Email: {user.email}")  # Debugging Log