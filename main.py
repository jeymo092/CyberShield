from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
import os
import urllib.parse
import logging

import models
import security
from database import engine, get_db
from oauth2 import oauth, get_oauth_user_data

logger = logging.getLogger(__name__)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://accounts.google.com https://apis.google.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' https://www.google.com data: https://*.googleusercontent.com; "
            "frame-src 'self' https://accounts.google.com; "
            "connect-src 'self' https://accounts.google.com https://www.googleapis.com; "
            "frame-ancestors 'none'; "
            "form-action 'self' https://accounts.google.com; "
            "base-uri 'self'; "
            "upgrade-insecure-requests; "
            "block-all-mixed-content"
        )
        return response

# Create database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# Add session middleware with enhanced security
app.add_middleware(
    SessionMiddleware, 
    secret_key=security.SECRET_KEY,
    max_age=3600,  # 1 hour
    same_site="lax",
    https_only=True,
    session_cookie="session"
)

# Configure CORS with stricter settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_URL", "http://localhost:8000")],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=3600,
)

# Rate limiting middleware
class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        now = datetime.utcnow()
        
        # Clean old requests
        self.requests = {ip: reqs for ip, reqs in self.requests.items() 
                        if (now - reqs[-1]).seconds < self.window_seconds}
        
        # Check rate limit
        if client_ip in self.requests:
            requests = self.requests[client_ip]
            if len(requests) >= self.max_requests:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests"}
                )
            requests.append(now)
        else:
            self.requests[client_ip] = [now]
        
        return await call_next(request)

# Add rate limiting
app.add_middleware(RateLimitMiddleware, max_requests=100, window_seconds=60)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Pydantic models for request/response
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    username: str
    email: str
    is_active: bool
    created_at: datetime
    oauth_provider: Optional[str] = None

    class Config:
        from_attributes = True

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    token_data = security.verify_token(token)
    user = db.query(models.User).filter(models.User.username == token_data.username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.post("/auth/register", response_model=UserResponse)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    # Check if user exists
    db_user = db.query(models.User).filter(
        (models.User.email == user.email) | (models.User.username == user.username)
    ).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email or username already registered")
    
    # Create new user
    hashed_password = security.get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/google/login")
async def google_login(request: Request):
    """Initiate Google OAuth login flow."""
    try:
        redirect_uri = f"{request.base_url}auth/google/callback"
        logger.debug(f"Starting Google login with redirect URI: {redirect_uri}")
        
        try:
            return await oauth.google.authorize_redirect(
                request,
                redirect_uri,
                prompt='select_account'  # Force Google account selection
            )
        except Exception as e:
            logger.error(f"Failed to initiate Google OAuth: {str(e)}", exc_info=True)
            return RedirectResponse(
                url=f"/?error={urllib.parse.quote('Failed to connect to Google. Please try again.')}"
            )
            
    except Exception as e:
        logger.error(f"Google login error: {str(e)}", exc_info=True)
        return RedirectResponse(
            url=f"/?error={urllib.parse.quote('Authentication failed. Please try again later.')}"
        )

@app.get("/auth/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    """Handle Google OAuth callback."""
    try:
        user_data = await get_oauth_user_data("google", request)
        
        # Check if user exists
        db_user = db.query(models.User).filter(
            (models.User.oauth_provider == "google") & 
            (models.User.oauth_id == user_data['oauth_id'])
        ).first()
        
        if not db_user:
            # Check if email exists
            email_user = db.query(models.User).filter(models.User.email == user_data['email']).first()
            if email_user:
                return RedirectResponse(
                    url=f"/static/auth.html?error={urllib.parse.quote('Email already registered with a different method.')}"
                )
            
            # Create new user
            db_user = models.User(
                email=user_data['email'],
                username=user_data['username'],
                oauth_provider=user_data['oauth_provider'],
                oauth_id=user_data['oauth_id'],
                oauth_data=user_data['oauth_data'],
                is_active=True
            )
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
        
        # Update last login
        db_user.last_login = datetime.utcnow()
        db.commit()
        
        # Create access token with longer expiration
        access_token_expires = timedelta(days=7)  # 7 days
        access_token = security.create_access_token(
            data={"sub": db_user.username}, expires_delta=access_token_expires
        )
        
        # Create response with cookie and redirect to dashboard
        response = RedirectResponse(
            url="/static/dashboard.html",
            status_code=status.HTTP_302_FOUND
        )
        
        # Set a more persistent token cookie
        response.set_cookie(
            key="auth_token",
            value=access_token,
            httponly=False,  # Allow JavaScript access
            secure=False,  # Allow HTTP in development
            samesite="lax",  # More permissive SameSite policy
            path="/",  # Available across all paths
            max_age=7 * 24 * 3600  # 7 days
        )
        
        return response
        
    except HTTPException as he:
        error_message = urllib.parse.quote(he.detail)
        return RedirectResponse(
            url=f"/static/auth.html?error={error_message}",
            status_code=status.HTTP_302_FOUND
        )
    except Exception as e:
        logger.error(f"Google callback error: {str(e)}", exc_info=True)
        return RedirectResponse(
            url=f"/static/auth.html?error={urllib.parse.quote('Authentication failed. Please try again later.')}",
            status_code=status.HTTP_302_FOUND
        )

@app.get("/auth/token/exchange")
async def exchange_oauth_token(request: Request):
    """Exchange temporary OAuth token for actual access token."""
    try:
        token = request.session.get('oauth_token')
        if not token:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "No token found"}
            )
        
        # Clear the token from session
        del request.session['oauth_token']
        
        return JSONResponse({"access_token": token, "token_type": "bearer"})
    except Exception as e:
        logger.error(f"Token exchange error: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Token exchange failed"}
        )

@app.post("/auth/refresh")
async def refresh_token(current_user: models.User = Depends(get_current_user)):
    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": current_user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/logout")
async def logout(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    blacklisted_token = models.BlacklistedToken(token=token)
    db.add(blacklisted_token)
    db.commit()
    return {"message": "Successfully logged out"}

@app.get("/auth/profile", response_model=UserResponse)
async def get_profile(current_user: models.User = Depends(get_current_user)):
    return current_user

@app.get("/auth/status")
async def get_auth_status(request: Request, db: Session = Depends(get_db)):
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return {"authenticated": False}
        
        token = auth_header.split(' ')[1]
        token_data = security.verify_token(token)
        
        user = db.query(models.User).filter(models.User.username == token_data.username).first()
        if not user:
            return {"authenticated": False}
            
        return {
            "authenticated": True,
            "user": {
                "username": user.username,
                "email": user.email,
                "oauth_provider": user.oauth_provider
            }
        }
    except:
        return {"authenticated": False}

@app.get("/")
async def read_root():
    static_file_path = os.path.join(os.getcwd(), "static", "index.html")
    if os.path.exists(static_file_path):
        return FileResponse(static_file_path)
    raise HTTPException(status_code=404, detail="Index file not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 