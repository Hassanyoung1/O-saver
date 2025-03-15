from typing import Optional
from typing_extensions import Annotated
from pydantic import BaseModel, EmailStr, Field, StringConstraints

class UserBase(BaseModel):
    """
    Base schema for User data validation.
    """
    name: str = Field(..., min_length=3, max_length=50)
    phone: Annotated[
        str,
        StringConstraints(min_length=10, max_length=15)
    ]    
    email: Optional[EmailStr] = None
    is_agent: bool = False

class UserCreate(BaseModel):
    name: str
    phone: str
    email: EmailStr
    password: str
    is_agent: bool

    
class UserResponse(UserBase):
    """
    Schema for user response (excluding password).
    """
    id: int

    class Config:
        orm_mode = True  # Allows SQLAlchemy models to be serialized as dictionaries

class LoginRequest(BaseModel):
    """
    Schema for login request.
    """
    phone: str
    password: str

class LoginSchema(BaseModel):
    """
    Schema for login response.
    """
    access_token: str
    token_type: str

class TokenData(BaseModel):
    """
    Schema for token payload.
    """
    user_id: int
    is_agent: bool
