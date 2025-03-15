from typing import Optional
from typing_extensions import Annotated
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, StringConstraints, field_validator


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
    phone: Optional[Annotated[str, StringConstraints(min_length=10, max_length=15)]] = None
    email: Optional[EmailStr] = None
    password: str

    @field_validator("phone", "email", mode="before")
    def check_phone_or_email(cls, value, info):
        """
        Ensures at least one of phone or email is provided.
        """
        field_name = info.field_name
        other_field = "email" if field_name == "phone" else "phone"
        
        # Get the values dict from info.data (available in validation context)
        if not value and not info.data.get(other_field):
            raise ValueError("Either phone or email must be provided.")
        return value

        

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



class PasswordResetRequest(BaseModel):
    """
    Schema for requesting a password reset.
    """
    email: Optional[EmailStr] = None
    phone: Optional[Annotated[str, StringConstraints(min_length=10, max_length=15)]] = None

    @field_validator("email", "phone")
    def check_either_email_or_phone(cls, value, info):
        """
        Ensure either phone or email is provided.
        """
        other_field = "email" if info.field_name == "phone" else "phone"
        
        if not value and not info.data.get(other_field):
            raise ValueError("Either email or phone must be provided.")
        return value


class PasswordResetVerify(BaseModel):
    """
    Schema for verifying password reset and setting a new password.
    """
    reset_token: str
    new_password: Annotated[str, StringConstraints(min_length=6)]
