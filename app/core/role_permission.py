from fastapi import Depends, HTTPException
from jose import jwt, JWTError
from app.core.config import settings
from app.models.user import UserRole
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_role(required_role: UserRole):
    """
    Middleware to enforce role-based access.
    """
    def role_checker(token: str = Depends(oauth2_scheme)):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            user_role = payload.get("role")
            if user_role != required_role.value:
                raise HTTPException(status_code=403, detail="Permission denied. Insufficient role.")
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
    return role_checker
