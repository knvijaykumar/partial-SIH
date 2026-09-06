from fastapi import FastAPI
from app.core.config import APP_NAME, APP_VERSION
from app.api.email_analysis import router as email_analysis_router


app = FastAPI(
    title=APP_NAME,
    description="AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform",
    version=APP_VERSION
)


app.include_router(email_analysis_router)


@app.get("/")
def root():
    return {
        "message": "SIH26106 Backend is running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }