from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, Date, Enum
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.schemas.user import UserRole

class User(Base):
    """
    User model representing both Agents and Contributors.

    Attributes:
        id (int): Unique user identifier.
        name (str): User's full name.
        email (str, optional): User's email (unique, nullable).
        phone (str): User's phone number (unique, required).
        password_hash (str): Hashed password.
        is_agent (bool): Determines if the user is an agent.
        created_by (int, optional): ID of the agent who registered this user (if applicable).
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    date_of_birth = Column(Date, nullable=False)
    address = Column(String, nullable=False)
    phone = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_agent = Column(Boolean, default=False)
    nationality = Column(String, nullable=False)
    gender = Column(String, nullable=False)
    occupation = Column(String, nullable=False)
    is_verified = Column(Boolean, default=False)
    otp_code = Column(String, nullable=True)
    created_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.CONTRIBUTOR)  # ✅ New field


    # Relationship: An agent can have multiple contributors
    contributors = relationship("User", backref="creator", remote_side=[id])