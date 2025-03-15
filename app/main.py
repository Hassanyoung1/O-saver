from fastapi import FastAPI
from app.core.config import settings
from app.core.database import engine, Base
from app.api.v1.routes import auth

from dotenv import load_dotenv
import os

# Load environment variables from .env file at startup
load_dotenv()


# Initialize FastAPI app
app = FastAPI(title=settings.PROJECT_NAME, version=settings.PROJECT_VERSION)

app.include_router(auth.router, prefix="/api/v1", tags=["Auth"])

# Create database tables
Base.metadata.create_all(bind=engine)


# Define a root endpoint
@app.get("/")
def root():
    return {"message": "Welcome to O-Saver API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
