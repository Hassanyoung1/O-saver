from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.core.config import settings
from app.models.user import User
from app.schemas.user import TokenData
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.core.database import SessionLocal
from app.services.email_service import EmailService  # Correct the import statement

class AuthService:
    """
    Authentication service for user registration, login, and token management.
    """
    
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    def hash_password(cls, password: str) -> str:
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


    @classmethod
    def generate_reset_token(cls, user: User) -> str:
        """
        Generates a secure password reset token.

        Args:
            user (User): The user requesting a password reset.

        Returns:
            str: A signed JWT reset token.
        """
        payload = {
            "user_id": user.id,
            "exp": datetime.utcnow() + timedelta(minutes=15),  # Token expires in 15 minutes
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    @classmethod
    def request_password_reset(cls, db: Session, email: Optional[str], phone: Optional[str]):
        """
        Initiates a password reset request by sending a reset token.

        Args:
            db (Session): Database session.
            email (str): Email of the user.
            phone (str): Phone number of the user.

        Returns:
            dict: Success message.
        """
        user = db.query(User).filter((User.email == email) | (User.phone == phone)).first()
        if not user:
            return {"error": "User not found"}, 404

        reset_token = cls.generate_reset_token(user)

        # Send token via email
        if user.email:
            EmailService.send_password_reset_email(user.email, reset_token)

        return {"message": "Password reset instructions sent to your email/phone."}@classmethod
    
    @classmethod
    def request_password_reset(cls, db: Session, email: Optional[str], phone: Optional[str]):
        """
        Initiates a password reset request by sending a reset token.

        Args:
            db (Session): Database session.
            email (str): Email of the user.
            phone (str): Phone number of the user.

        Returns:
            tuple: (result, status_code)
        """
        user = db.query(User).filter((User.email == email) | (User.phone == phone)).first()
        if not user:
            return {"error": "User not found"}, 404

        reset_token = cls.generate_reset_token(user)

        # Send token via email
        if user.email:
            EmailService.send_password_reset_email(user.email, reset_token)

        return {"message": "Password reset instructions sent to your email/phone."}, 200

    @classmethod
    def verify_password_reset(cls, db: Session, reset_token: str, new_password: str):
        """
        Verifies the reset token and updates the user's password.

        Args:
            db (Session): Database session.
            reset_token (str): Reset token provided by the user.
            new_password (str): New password.

        Returns:
            tuple: (result, status_code)
        """
        try:
            payload = jwt.decode(reset_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            user_id = payload["user_id"]
        except jwt.ExpiredSignatureError:
            return {"error": "Reset token expired"}, 400
        except jwt.JWTError:
            return {"error": "Invalid reset token"}, 400

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return {"error": "User not found"}, 404

        # Update password
        user.hashed_password = cls.hash_password(new_password)
        db.commit()

        return {"message": "Password reset successful"}, 200