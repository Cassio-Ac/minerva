"""
Telegram Blacklist API Endpoints
REST API for managing Telegram message blacklist filters
"""

import logging
from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.telegram_blacklist import (
    TelegramBlacklistCreateRequest,
    TelegramBlacklistUpdateRequest,
    TelegramBlacklistResponse,
    TelegramBlacklistListResponse,
)
from app.models.telegram_blacklist import TelegramMessageBlacklist
from app.db.database import get_db
from app.core.dependencies import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/telegram/blacklist", tags=["Telegram Blacklist"])


# ==================== CRUD Endpoints ====================

@router.post("", response_model=TelegramBlacklistResponse, status_code=status.HTTP_201_CREATED)
async def create_blacklist_entry(
    request: TelegramBlacklistCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Create a new blacklist entry to filter messages from search results

    - **pattern**: String or regex pattern to match
    - **description**: Optional description explaining why this is blacklisted
    - **is_regex**: Whether the pattern is a regular expression
    - **case_sensitive**: Whether matching should be case sensitive
    - **is_active**: Whether this filter is currently active
    """
    try:
        entry = TelegramMessageBlacklist(
            pattern=request.pattern,
            description=request.description,
            is_regex=request.is_regex,
            case_sensitive=request.case_sensitive,
            is_active=request.is_active,
            created_by=current_user.id if current_user else None
        )

        db.add(entry)
        await db.flush()
        await db.commit()
        await db.refresh(entry)

        logger.info(f"✅ Created blacklist entry: {entry.pattern}")
        return entry

    except Exception as e:
        await db.rollback()
        logger.error(f"❌ Error creating blacklist entry: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating blacklist entry: {str(e)}"
        )


@router.get("", response_model=TelegramBlacklistListResponse)
async def list_blacklist_entries(
    include_inactive: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    List all blacklist entries

    - **include_inactive**: If True, includes inactive entries
    """
    try:
        from sqlalchemy import select

        stmt = select(TelegramMessageBlacklist)

        if not include_inactive:
            stmt = stmt.where(TelegramMessageBlacklist.is_active == True)

        stmt = stmt.order_by(TelegramMessageBlacklist.created_at.desc())
        result = await db.execute(stmt)
        entries = result.scalars().all()

        return TelegramBlacklistListResponse(
            total=len(entries),
            items=entries
        )

    except Exception as e:
        logger.error(f"❌ Error listing blacklist entries: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error listing blacklist entries: {str(e)}"
        )


@router.get("/{entry_id}", response_model=TelegramBlacklistResponse)
async def get_blacklist_entry(
    entry_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get a specific blacklist entry by ID
    """
    try:
        from sqlalchemy import select

        stmt = select(TelegramMessageBlacklist).where(
            TelegramMessageBlacklist.id == entry_id
        )
        result = await db.execute(stmt)
        entry = result.scalar_one_or_none()

        if not entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Blacklist entry not found"
            )

        return entry

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error getting blacklist entry: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting blacklist entry: {str(e)}"
        )


@router.put("/{entry_id}", response_model=TelegramBlacklistResponse)
async def update_blacklist_entry(
    entry_id: UUID,
    request: TelegramBlacklistUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Update a blacklist entry
    """
    try:
        from sqlalchemy import select

        stmt = select(TelegramMessageBlacklist).where(
            TelegramMessageBlacklist.id == entry_id
        )
        result = await db.execute(stmt)
        entry = result.scalar_one_or_none()

        if not entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Blacklist entry not found"
            )

        # Update fields if provided
        if request.pattern is not None:
            entry.pattern = request.pattern
        if request.description is not None:
            entry.description = request.description
        if request.is_regex is not None:
            entry.is_regex = request.is_regex
        if request.case_sensitive is not None:
            entry.case_sensitive = request.case_sensitive
        if request.is_active is not None:
            entry.is_active = request.is_active

        await db.commit()
        await db.refresh(entry)

        logger.info(f"✅ Updated blacklist entry: {entry_id}")
        return entry

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"❌ Error updating blacklist entry: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating blacklist entry: {str(e)}"
        )


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_blacklist_entry(
    entry_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Delete a blacklist entry permanently
    """
    try:
        from sqlalchemy import select

        stmt = select(TelegramMessageBlacklist).where(
            TelegramMessageBlacklist.id == entry_id
        )
        result = await db.execute(stmt)
        entry = result.scalar_one_or_none()

        if not entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Blacklist entry not found"
            )

        await db.delete(entry)
        await db.commit()

        logger.info(f"✅ Deleted blacklist entry: {entry_id}")

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"❌ Error deleting blacklist entry: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting blacklist entry: {str(e)}"
        )


@router.post("/{entry_id}/toggle", response_model=TelegramBlacklistResponse)
async def toggle_blacklist_entry(
    entry_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Toggle the active status of a blacklist entry (enable/disable)
    """
    try:
        from sqlalchemy import select

        stmt = select(TelegramMessageBlacklist).where(
            TelegramMessageBlacklist.id == entry_id
        )
        result = await db.execute(stmt)
        entry = result.scalar_one_or_none()

        if not entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Blacklist entry not found"
            )

        entry.is_active = not entry.is_active

        await db.commit()
        await db.refresh(entry)

        status_text = "activated" if entry.is_active else "deactivated"
        logger.info(f"✅ {status_text.capitalize()} blacklist entry: {entry_id}")
        return entry

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"❌ Error toggling blacklist entry: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error toggling blacklist entry: {str(e)}"
        )
