from sqlalchemy import Column, String, Integer, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from app.core.database import Base

class User(Base):
    """
    User model representing both Agents and Contributors.

    Attributes:
        id (int): Unique user identifier.
        name (str): User's full name.
        email (str, optional): User's email (unique, nullable).
        phone (str): User's phone number (unique, required).
        password (str): Hashed password.
        is_agent (bool): Determines if the user is an agent.
        created_by (int, optional): ID of the agent who registered this user (if applicable).
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=True)
    phone = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_agent = Column(Boolean, default=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # If a contributor is registered by an agent
    is_verified = Column(Boolean, default=False)  # ✅ User verification status
    otp_code = Column(String, nullable=True) 

    # Relationship: An agent can have multiple contributors
    contributors = relationship("User", remote_side=[id])
