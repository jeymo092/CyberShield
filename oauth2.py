from typing import Optional
from fastapi import HTTPException, status
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from starlette.requests import Request
from datetime import datetime
import logging
import httpx

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
config = Config(".env")

# OAuth settings
GOOGLE_CLIENT_ID = config("GOOGLE_CLIENT_ID", default=None)
GOOGLE_CLIENT_SECRET = config("GOOGLE_CLIENT_SECRET", default=None)
CALLBACK_URL = config("CALLBACK_URL", default="http://localhost:8000")

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise ValueError("Missing Google OAuth credentials in .env file")

logger.debug(f"Callback URL: {CALLBACK_URL}")
logger.debug(f"Google Client ID: {GOOGLE_CLIENT_ID[:10]}...")  # Only log first 10 chars for security

# Configure httpx client with custom timeout
client = httpx.AsyncClient(
    timeout=httpx.Timeout(30.0, connect=10.0),
    verify=True,
    follow_redirects=True
)

# OAuth object with custom client
oauth = OAuth()

# Google configuration
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_post',
        'code_challenge_method': None,
        'timeout': 30.0
    }
)

async def get_oauth_user_data(provider: str, request: Request) -> dict:
    """Get user data from OAuth provider."""
    try:
        if provider == "google":
            logger.debug("Starting Google OAuth token exchange")
            
            try:
                token = await oauth.google.authorize_access_token(request)
            except Exception as e:
                logger.error(f"Token exchange error: {str(e)}", exc_info=True)
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Failed to connect to Google authentication service. Please try again."
                )

            logger.debug(f"Received token response: {token.keys()}")
            
            if not token:
                logger.error("Failed to get access token")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Could not get access token"
                )
            
            logger.debug("Getting user info from Google")
            try:
                resp = await oauth.google.get(
                    'https://www.googleapis.com/oauth2/v3/userinfo',
                    token=token,
                    timeout=30.0
                )
            except httpx.TimeoutException:
                logger.error("Timeout while fetching user info")
                raise HTTPException(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    detail="Connection to Google timed out. Please try again."
                )
            except Exception as e:
                logger.error(f"Error fetching user info: {str(e)}", exc_info=True)
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Failed to fetch user information from Google."
                )

            if not resp:
                logger.error("Failed to get user info")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Could not get user info"
                )
            
            user = resp.json()
            logger.debug(f"Successfully got user info for email: {user.get('email', 'unknown')}")
            
            return {
                'oauth_provider': 'google',
                'oauth_id': user['sub'],
                'email': user['email'],
                'username': user['email'].split('@')[0],
                'oauth_data': {
                    'name': user.get('name'),
                    'picture': user.get('picture'),
                    'locale': user.get('locale')
                }
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only Google OAuth is supported"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed. Please try again later."
        ) 