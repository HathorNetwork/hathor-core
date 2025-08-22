"""
Main FastAPI application for Nano Contracts IDE
"""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog

from api.contracts import router as contracts_router
from api.validation import router as validation_router
from api.storage import router as storage_router
from api.network import router as network_router
from core.config import get_settings


logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info("Starting Nano Contracts IDE Backend")

    # Initialize services here if needed

    yield

    # Shutdown
    logger.info("Shutting down Nano Contracts IDE Backend")


# Create FastAPI application
app = FastAPI(
    title="Nano Contracts IDE API",
    description="Backend API for Hathor Nano Contracts IDE",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(
    contracts_router, prefix="/api/contracts", tags=["contracts"])
app.include_router(validation_router,
                   prefix="/api/validation", tags=["validation"])
app.include_router(storage_router, prefix="/api/storage", tags=["storage"])
app.include_router(network_router, prefix="/api/network", tags=["network"])


@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "Nano Contracts IDE API", "version": "1.0.0"}


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error("Unhandled exception", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"message": "Internal server error"}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
