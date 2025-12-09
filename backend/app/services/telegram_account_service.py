"""
Telegram Account Service
"""
from typing import List, Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException

from app.models.telegram_account import TelegramAccount
from app.schemas.telegram_account import TelegramAccountCreate, TelegramAccountUpdate, TelegramAccountResponse, TelegramAccountDetail
from app.services.encryption_service import EncryptionService


class TelegramAccountService:
    """Service for managing Telegram accounts"""

    def __init__(self, db: AsyncSession, encryption_service: EncryptionService):
        self.db = db
        self.encryption_service = encryption_service

    async def get_all(self) -> List[TelegramAccountResponse]:
        """Get all Telegram accounts"""
        result = await self.db.execute(select(TelegramAccount).order_by(TelegramAccount.created_at.desc()))
        accounts = result.scalars().all()

        return [
            TelegramAccountResponse(
                id=acc.id,
                name=acc.name,
                phone_masked=self._mask_phone(self.encryption_service.decrypt(acc.phone_encrypted)),
                session_name=acc.session_name,
                is_active=acc.is_active,
                created_at=acc.created_at,
                updated_at=acc.updated_at
            )
            for acc in accounts
        ]

    async def get_by_id(self, account_id: UUID) -> Optional[TelegramAccountResponse]:
        """Get Telegram account by ID"""
        result = await self.db.execute(select(TelegramAccount).where(TelegramAccount.id == account_id))
        account = result.scalar_one_or_none()

        if not account:
            return None

        return TelegramAccountResponse(
            id=account.id,
            name=account.name,
            phone_masked=self._mask_phone(self.encryption_service.decrypt(account.phone_encrypted)),
            session_name=account.session_name,
            is_active=account.is_active,
            created_at=account.created_at,
            updated_at=account.updated_at
        )

    async def get_decrypted(self, account_id: UUID) -> Optional[TelegramAccountDetail]:
        """Get decrypted Telegram account (for internal use only)"""
        result = await self.db.execute(select(TelegramAccount).where(TelegramAccount.id == account_id))
        account = result.scalar_one_or_none()

        if not account:
            return None

        return TelegramAccountDetail(
            id=account.id,
            name=account.name,
            api_id=int(self.encryption_service.decrypt(account.api_id_encrypted)),
            api_hash=self.encryption_service.decrypt(account.api_hash_encrypted),
            phone=self.encryption_service.decrypt(account.phone_encrypted),
            phone_masked=self._mask_phone(self.encryption_service.decrypt(account.phone_encrypted)),
            session_name=account.session_name,
            is_active=account.is_active,
            created_at=account.created_at,
            updated_at=account.updated_at
        )

    async def get_all_decrypted(self, active_only: bool = False) -> List[TelegramAccountDetail]:
        """Get all decrypted Telegram accounts (for internal use only)"""
        query = select(TelegramAccount)
        if active_only:
            query = query.where(TelegramAccount.is_active == True)

        result = await self.db.execute(query.order_by(TelegramAccount.created_at.desc()))
        accounts = result.scalars().all()

        return [
            TelegramAccountDetail(
                id=acc.id,
                name=acc.name,
                api_id=int(self.encryption_service.decrypt(acc.api_id_encrypted)),
                api_hash=self.encryption_service.decrypt(acc.api_hash_encrypted),
                phone=self.encryption_service.decrypt(acc.phone_encrypted),
                phone_masked=self._mask_phone(self.encryption_service.decrypt(acc.phone_encrypted)),
                session_name=acc.session_name,
                is_active=acc.is_active,
                created_at=acc.created_at,
                updated_at=acc.updated_at
            )
            for acc in accounts
        ]

    async def create(self, account_data: TelegramAccountCreate) -> TelegramAccountResponse:
        """Create a new Telegram account"""
        # Check if name already exists
        result = await self.db.execute(select(TelegramAccount).where(TelegramAccount.name == account_data.name))
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Account with this name already exists")

        # Check if session_name already exists
        result = await self.db.execute(select(TelegramAccount).where(TelegramAccount.session_name == account_data.session_name))
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Account with this session name already exists")

        # Encrypt sensitive data
        account = TelegramAccount(
            name=account_data.name,
            api_id_encrypted=self.encryption_service.encrypt(str(account_data.api_id)),
            api_hash_encrypted=self.encryption_service.encrypt(account_data.api_hash),
            phone_encrypted=self.encryption_service.encrypt(account_data.phone),
            session_name=account_data.session_name,
            is_active=account_data.is_active
        )

        self.db.add(account)
        await self.db.commit()
        await self.db.refresh(account)

        return TelegramAccountResponse(
            id=account.id,
            name=account.name,
            phone_masked=self._mask_phone(account_data.phone),
            session_name=account.session_name,
            is_active=account.is_active,
            created_at=account.created_at,
            updated_at=account.updated_at
        )

    async def update(self, account_id: UUID, account_data: TelegramAccountUpdate) -> Optional[TelegramAccountResponse]:
        """Update a Telegram account"""
        result = await self.db.execute(select(TelegramAccount).where(TelegramAccount.id == account_id))
        account = result.scalar_one_or_none()

        if not account:
            return None

        # Check if new name already exists (if changing name)
        if account_data.name and account_data.name != account.name:
            result = await self.db.execute(select(TelegramAccount).where(TelegramAccount.name == account_data.name))
            if result.scalar_one_or_none():
                raise HTTPException(status_code=400, detail="Account with this name already exists")

        # Check if new session_name already exists (if changing session_name)
        if account_data.session_name and account_data.session_name != account.session_name:
            result = await self.db.execute(select(TelegramAccount).where(TelegramAccount.session_name == account_data.session_name))
            if result.scalar_one_or_none():
                raise HTTPException(status_code=400, detail="Account with this session name already exists")

        # Update fields
        if account_data.name:
            account.name = account_data.name
        if account_data.api_id:
            account.api_id_encrypted = self.encryption_service.encrypt(str(account_data.api_id))
        if account_data.api_hash:
            account.api_hash_encrypted = self.encryption_service.encrypt(account_data.api_hash)
        if account_data.phone:
            account.phone_encrypted = self.encryption_service.encrypt(account_data.phone)
        if account_data.session_name:
            account.session_name = account_data.session_name
        if account_data.is_active is not None:
            account.is_active = account_data.is_active

        await self.db.commit()
        await self.db.refresh(account)

        return TelegramAccountResponse(
            id=account.id,
            name=account.name,
            phone_masked=self._mask_phone(self.encryption_service.decrypt(account.phone_encrypted)),
            session_name=account.session_name,
            is_active=account.is_active,
            created_at=account.created_at,
            updated_at=account.updated_at
        )

    async def delete(self, account_id: UUID) -> bool:
        """Delete a Telegram account"""
        result = await self.db.execute(select(TelegramAccount).where(TelegramAccount.id == account_id))
        account = result.scalar_one_or_none()

        if not account:
            return False

        await self.db.delete(account)
        await self.db.commit()
        return True

    def _mask_phone(self, phone: str) -> str:
        """Mask phone number (ex: +5585997783113 -> +55***********13)"""
        if len(phone) < 7:
            return phone
        return f"{phone[:3]}{'*' * (len(phone) - 5)}{phone[-2:]}"
