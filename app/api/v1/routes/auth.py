from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.schemas.user import UserCreate, UserResponse, LoginRequest
from app.services.auth import AuthService
from app.models.user import User
from app.core.database import SessionLocal

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
    Registers a new user (Agent or Contributor).
    
    - Hashes the password before saving.
    - Prevents duplicate phone number registration.
    """
    # Check if phone number is already registered
    existing_user = db.query(User).filter(User.phone == user_data.phone).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Phone number already registered")

    # Hash password before saving
    password = AuthService.password(user_data.password)
    
    # ✅ Create user with password_hash instead of password
    new_user = User(
        name=user_data.name,
        phone=user_data.phone,
        email=user_data.email,
        password=password,  # ✅ Fixed field name
        is_agent=user_data.is_agent
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login")
def login_user(login_data: LoginRequest, db: Session = Depends(get_db)):
    """
    Logs in a user and returns an access token.
    """
    user = db.query(User).filter(User.phone == login_data.phone).first()
    if not user or not AuthService.verify_password(login_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = AuthService.create_access_token(user)
    return {"access_token": token, "token_type": "bearer"}
