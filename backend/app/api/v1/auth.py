"""
Authentication API
Endpoints for user login, registration, and profile management
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.user import User, UserRole
from app.schemas.user import (
    UserCreate,
    UserLogin,
    UserResponse,
    Token,
    UserChangePassword,
)
from app.services.auth_service import AuthService, ACCESS_TOKEN_EXPIRE_MINUTES
from app.core.dependencies import get_current_user, get_current_active_user
from datetime import timedelta


router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user

    **Permissions**: Public (anyone can register as READER)

    **Note**: Only READER role can be self-registered.
    Admin must create POWER and ADMIN users.
    """
    # Check if username already exists
    existing_user = await AuthService.get_user_by_username(db, user_data.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    # Check if email already exists
    existing_email = await AuthService.get_user_by_email(db, user_data.email)
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Force READER role for self-registration (security)
    # Only admins can create POWER/ADMIN users via user management
    if user_data.role != UserRole.READER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Self-registration only allows READER role. Contact admin for other roles."
        )

    # Create user
    user = await AuthService.create_user(
        db=db,
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
        full_name=user_data.full_name,
        role=UserRole.READER
    )

    # Return user data with permissions
    user_dict = user.to_dict()
    user_dict.update({
        "can_manage_users": user.can_manage_users,
        "can_use_llm": user.can_use_llm,
        "can_create_dashboards": user.can_create_dashboards,
        "can_configure_system": user.can_configure_system,
    })

    return user_dict


@router.post("/login", response_model=Token)
async def login(
    credentials: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """
    Login with username/email and password

    **Permissions**: Public

    **Returns**: JWT access token and user info
    """
    # Authenticate user
    user = await AuthService.authenticate_user(db, credentials.username, credentials.password)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = AuthService.create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "role": user.role.value if isinstance(user.role, UserRole) else user.role
        },
        expires_delta=access_token_expires
    )

    # Prepare user response
    user_dict = user.to_dict()
    user_dict.update({
        "can_manage_users": user.can_manage_users,
        "can_use_llm": user.can_use_llm,
        "can_create_dashboards": user.can_create_dashboards,
        "can_upload_csv": user.can_upload_csv,
        "has_index_restrictions": user.has_index_restrictions,
        "can_configure_system": user.can_configure_system,
        "assigned_es_server_id": None,  # Temporariamente None até migração
    })

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_dict
    }


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current user information

    **Permissions**: Authenticated user

    **Returns**: Current user profile
    """
    user_dict = current_user.to_dict()
    user_dict.update({
        "can_manage_users": current_user.can_manage_users,
        "can_use_llm": current_user.can_use_llm,
        "can_create_dashboards": current_user.can_create_dashboards,
        "can_upload_csv": current_user.can_upload_csv,
        "has_index_restrictions": current_user.has_index_restrictions,
        "can_configure_system": current_user.can_configure_system,
        "assigned_es_server_id": None,  # Temporariamente None até migração
    })

    return user_dict


@router.post("/change-password", response_model=UserResponse)
async def change_password(
    password_data: UserChangePassword,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Change current user's password

    **Permissions**: Authenticated user

    **Returns**: Updated user profile
    """
    # Verify current password
    if not AuthService.verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )

    # Change password
    user = await AuthService.change_password(db, current_user, password_data.new_password)

    user_dict = user.to_dict()
    user_dict.update({
        "can_manage_users": user.can_manage_users,
        "can_use_llm": user.can_use_llm,
        "can_create_dashboards": user.can_create_dashboards,
        "can_upload_csv": user.can_upload_csv,
        "has_index_restrictions": user.has_index_restrictions,
        "can_configure_system": user.can_configure_system,
        "assigned_es_server_id": None,  # Temporariamente None até migração
    })

    return user_dict


@router.post("/logout")
async def logout():
    """
    Logout user (client-side token removal)

    **Permissions**: Authenticated user

    **Note**: Since we're using JWT, actual logout happens client-side by removing the token.
    This endpoint is just for consistency/future expansion (e.g., token blacklist).
    """
    return {"message": "Logged out successfully"}
