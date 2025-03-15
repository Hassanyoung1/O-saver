from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.schemas.user import UserCreate, UserResponse, LoginRequest, LoginSchema
from app.services.auth import AuthService
from app.models.user import User
from app.core.database import SessionLocal
from app.services.otp_service import OTPService
from app.services.email_service import EmailService
from pydantic import BaseModel
from app.utils.security import Security 




router = APIRouter()

def get_db():
    """
    Dependency to get the database session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/register")
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """
    Registers a new user and sends OTP for email verification.
    """
    existing_user = db.query(User).filter(User.phone == user_data.phone).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Phone number already registered")

    # Hash password
    hashed_password = AuthService.hashed_password(user_data.password)

    # Generate OTP
    otp_code = OTPService.generate_otp()

    # Create new user with is_verified=False
    new_user = User(
        name=user_data.name,
        phone=user_data.phone,
        email=user_data.email,
        password_hash=hashed_password,
        is_agent=user_data.is_agent,
        is_verified=False,  # ✅ Not verified yet
        otp_code=otp_code
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    print(f"✅ OTP for {user_data.email}: {otp_code}")  # Print in console for dev testing


    # Send OTP via Email
    email_sent = EmailService.send_otp_email(new_user.email, otp_code)
    if not email_sent:
        raise HTTPException(status_code=500, detail="Error sending OTP email")

    return {
        "message": "User registered successfully. Please verify OTP.",
        "otp_for_testing": otp_code 
        }


class VerifyOTP(BaseModel):
    email: str
    otp_code: str



@router.post("/verify-otp")
def verify_otp(data: VerifyOTP, db: Session = Depends(get_db)):
    """
    Verifies the OTP code and activates the user account.
    """
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.otp_code != data.otp_code:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Mark user as verified
    user.is_verified = True
    user.otp_code = None  # Clear OTP after verification
    db.commit()

    return {"message": "Email verified successfully!"}




@router.post("/login", response_model=LoginSchema)
def login(user_data: LoginRequest, db: Session = Depends(get_db)):
    """
    Allows users to log in only if their email is verified.
    """
    user = db.query(User).filter(
        (User.email == user_data.email) | (User.phone == user_data.phone)
    ).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.is_verified:
        raise HTTPException(status_code=400, detail="Email not verified. Please check your email.")

    # Verify password
    if not AuthService.verify_password(user_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate JWT Token
    access_token = AuthService.create_access_token(user)

    return {"access_token": access_token, "token_type": "bearer"}