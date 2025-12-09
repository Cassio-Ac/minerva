"""
User Management API
Endpoints for managing users (admin only)
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.user import User, UserRole
from app.schemas.user import UserCreate, UserUpdate, UserResponse, UserListResponse
from app.services.auth_service import AuthService
from app.core.dependencies import get_current_admin_user


router = APIRouter()


@router.get("/", response_model=List[UserListResponse])
async def list_users(
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Max number of users to return"),
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all users

    **Permissions**: Admin only

    **Returns**: List of users (without sensitive info)
    """
    users = await AuthService.list_users(db, skip=skip, limit=limit)

    return [
        {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role.value if isinstance(user.role, UserRole) else user.role,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
        }
        for user in users
    ]


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get user by ID

    **Permissions**: Admin only

    **Returns**: User details
    """
    user = await AuthService.get_user_by_id(db, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user_dict = user.to_dict()
    user_dict.update({
        "can_manage_users": user.can_manage_users,
        "can_use_llm": user.can_use_llm,
        "can_create_dashboards": user.can_create_dashboards,
        "can_upload_csv": user.can_upload_csv,
        "has_index_restrictions": user.has_index_restrictions,
        "can_configure_system": user.can_configure_system,
        "assigned_es_server_id": str(user.assigned_es_server_id) if user.assigned_es_server_id else None,
    })

    return user_dict


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new user (any role)

    **Permissions**: Admin only

    **Note**: Admins can create users with any role (READER, POWER, ADMIN)
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

    # Create user with specified role
    user = await AuthService.create_user(
        db=db,
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
        full_name=user_data.full_name,
        role=user_data.role,
        assigned_es_server_id=user_data.assigned_es_server_id
    )

    user_dict = user.to_dict()
    user_dict.update({
        "can_manage_users": user.can_manage_users,
        "can_use_llm": user.can_use_llm,
        "can_create_dashboards": user.can_create_dashboards,
        "can_upload_csv": user.can_upload_csv,
        "has_index_restrictions": user.has_index_restrictions,
        "can_configure_system": user.can_configure_system,
        "assigned_es_server_id": str(user.assigned_es_server_id) if user.assigned_es_server_id else None,
    })

    return user_dict


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update user information

    **Permissions**: Admin only

    **Note**: Can update email, full_name, role, is_active
    """
    user = await AuthService.get_user_by_id(db, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Prevent admin from deactivating themselves
    if str(user.id) == str(current_user.id) and user_data.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account"
        )

    # Check if new email already exists (if changing email)
    if user_data.email and user_data.email.lower() != user.email:
        existing_email = await AuthService.get_user_by_email(db, user_data.email)
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

    # Update user
    user = await AuthService.update_user(
        db=db,
        user=user,
        email=user_data.email,
        full_name=user_data.full_name,
        role=user_data.role,
        is_active=user_data.is_active,
        assigned_es_server_id=user_data.assigned_es_server_id
    )

    user_dict = user.to_dict()
    user_dict.update({
        "can_manage_users": user.can_manage_users,
        "can_use_llm": user.can_use_llm,
        "can_create_dashboards": user.can_create_dashboards,
        "can_upload_csv": user.can_upload_csv,
        "has_index_restrictions": user.has_index_restrictions,
        "can_configure_system": user.can_configure_system,
        "assigned_es_server_id": str(user.assigned_es_server_id) if user.assigned_es_server_id else None,
    })

    return user_dict


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete user

    **Permissions**: Admin only

    **Warning**: This will also delete all user's dashboards and permissions!
    """
    user = await AuthService.get_user_by_id(db, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Prevent admin from deleting themselves
    if str(user.id) == str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )

    # Delete user (CASCADE will handle permissions and shares)
    await AuthService.delete_user(db, user)

    return None


@router.post("/{user_id}/reset-password", response_model=dict)
async def admin_reset_password(
    user_id: str,
    new_password: str = Query(..., min_length=8, description="New password"),
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Admin reset user password

    **Permissions**: Admin only

    **Note**: Admin can reset any user's password without knowing the current one
    """
    user = await AuthService.get_user_by_id(db, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Reset password
    await AuthService.change_password(db, user, new_password)

    return {
        "message": f"Password reset successfully for user {user.username}",
        "user_id": str(user.id)
    }
