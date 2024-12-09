from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
import logging
import asyncio
from scanner import SecurityScanner, scan_repository_handler
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state
app_state = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan manager for the FastAPI application with proper startup/shutdown events
    """
    try:
        # Startup
        logger.info("Starting application initialization")
        app_state['initialized'] = False
        
        # Initialize your resources here
        # Note: Keep this minimal and move heavy initialization to background_init
        
        # Signal that basic initialization is complete
        app_state['initialized'] = True
        
        yield
        
    finally:
        # Shutdown
        logger.info("Shutting down application")
        # Cleanup resources if needed
        app_state.clear()

app = FastAPI(
    title="Security Scanner API",
    description="API for scanning GitHub repositories",
    version="1.0.0",
    lifespan=lifespan
)

async def background_init() -> None:
    """
    Handle heavy initialization tasks in background
    Returns when initialization is complete
    """
    try:
        # Add your heavy initialization tasks here
        # For example: database connections, cache warming, etc.
        await asyncio.sleep(0.1)  # Prevent blocking
        
    except Exception as e:
        logger.error(f"Background initialization error: {str(e)}")
        raise

@app.on_event("startup")
async def startup_event() -> None:
    """
    Startup event handler that triggers background initialization
    """
    asyncio.create_task(background_init())

@app.post("/api/v1/scan")
async def scan_repository(
    owner: str,
    repo: str,
    installation_id: str,
    user_id: str
) -> Dict[str, Any]:
    """
    Endpoint to scan a repository
    
    Args:
        owner: GitHub repository owner
        repo: GitHub repository name
        installation_id: GitHub installation ID
        user_id: User identifier
        
    Returns:
        Dict containing scan results or error details
    """
    if not app_state.get('initialized'):
        raise HTTPException(
            status_code=503,
            detail="Service is starting up. Please try again in a moment."
        )
        
    try:
        # Construct the repository URL
        repo_url = f"https://github.com/{owner}/{repo}"
        
        # Get installation token using the installation ID
        installation_token = app.git_integration.get_access_token(int(installation_id)).token
        
        result = await scan_repository_handler(
            repo_url=repo_url,
            installation_token=installation_token,
            user_id=user_id
        )
        
        if not result['success']:
            raise HTTPException(
                status_code=400,
                detail=result.get('error', {'message': 'Scan failed'})
            )
            
        return result
        
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={"message": "Internal server error", "error": str(e)}
        )

@app.get("/api/v1/analysis/{owner}/{repo}/result")
async def get_analysis_findings(
    owner: str,
    repo: str
) -> Dict[str, Any]:
    """
    Get analysis findings for a repository
    
    Args:
        owner: Repository owner
        repo: Repository name
        
    Returns:
        Dict containing analysis findings
    """
    if not app_state.get('initialized'):
        raise HTTPException(
            status_code=503,
            detail="Service is starting up. Please try again in a moment."
        )
    
    # Implement your analysis retrieval logic here
    raise HTTPException(
        status_code=501,
        detail="Not implemented"
    )

# Health check endpoint
@app.get("/health")
async def health_check() -> Dict[str, str]:
    """
    Health check endpoint
    
    Returns:
        Dict containing service status
    """
    return {
        "status": "healthy",
        "initialized": str(app_state.get('initialized', False))
    }