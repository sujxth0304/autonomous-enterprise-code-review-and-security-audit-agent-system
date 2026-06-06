"""GitHub OAuth authentication router."""

from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.schemas.user import Token, UserRead

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_API = "https://api.github.com/user"


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


async def get_current_user(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Decode JWT and return current user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        github_id: str = payload.get("github_id")
        if not github_id:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.github_id == github_id))
    user = result.scalar_one_or_none()
    if not user:
        raise credentials_exception
    return user


@router.get("/github")
async def github_login() -> RedirectResponse:
    """Redirect user to GitHub OAuth authorization page."""
    params = f"client_id={settings.GITHUB_CLIENT_ID}&scope=read:user,user:email"
    return RedirectResponse(url=f"{GITHUB_AUTHORIZE_URL}?{params}")


@router.get("/callback")
async def github_callback(code: str, db: AsyncSession = Depends(get_db)) -> Token:
    """Handle GitHub OAuth callback, exchange code for JWT."""
    # Exchange code for GitHub access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        if token_response.status_code != 200:
            raise HTTPException(status_code=400, detail="GitHub token exchange failed")

        token_data = token_response.json()
        github_token = token_data.get("access_token")
        if not github_token:
            raise HTTPException(status_code=400, detail="No access token in response")

        # Fetch user info from GitHub
        user_response = await client.get(
            GITHUB_USER_API,
            headers={"Authorization": f"Bearer {github_token}", "Accept": "application/json"},
        )
        if user_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch GitHub user")

        gh_user = user_response.json()

    github_id = str(gh_user["id"])

    # Upsert user in DB
    result = await db.execute(select(User).where(User.github_id == github_id))
    user = result.scalar_one_or_none()

    if not user:
        user = User(
            github_id=github_id,
            login=gh_user["login"],
            email=gh_user.get("email"),
            name=gh_user.get("name"),
            avatar_url=gh_user.get("avatar_url"),
        )
        db.add(user)
    else:
        user.login = gh_user["login"]
        user.email = gh_user.get("email")
        user.name = gh_user.get("name")
        user.avatar_url = gh_user.get("avatar_url")
        user.last_login = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(user)

    access_token = create_access_token(
        data={"sub": str(user.id), "github_id": github_id, "role": user.role}
    )

    logger.info("auth.login_success", user=user.login, github_id=github_id)

    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserRead)
async def get_me(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    """Return current authenticated user."""
    user = await get_current_user(token=token, db=db)
    return UserRead.model_validate(user)


@router.post("/refresh", response_model=Token)
async def refresh_token(
    token: str,
) -> Token:
    """Refresh an expiring JWT token."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": False},
        )
        github_id = payload.get("github_id")
        role = payload.get("role", "viewer")
        sub = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    new_token = create_access_token(data={"sub": sub, "github_id": github_id, "role": role})
    return Token(
        access_token=new_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
