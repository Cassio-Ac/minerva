"""
Migration script to re-encrypt existing API keys with new salt-per-record method

IMPORTANT: Run this ONCE after deploying the new encryption service
"""

import asyncio
import sys
from sqlalchemy import select
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Add parent directory to path
sys.path.insert(0, '/app')

from app.db.database import AsyncSessionLocal
from app.models.llm_provider import LLMProvider
from app.core.config import settings


def old_decrypt(encrypted_text: str, secret_key: str) -> str:
    """Decrypt using OLD method (static salt)"""
    if not encrypted_text:
        return ""

    # OLD method: static salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'dashboard_ai_salt',  # OLD static salt
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
    cipher = Fernet(key)

    decrypted_bytes = cipher.decrypt(encrypted_text.encode())
    return decrypted_bytes.decode('utf-8')


def new_encrypt(plaintext: str, secret_key: str) -> str:
    """Encrypt using NEW method (unique salt per record)"""
    if not plaintext:
        return ""

    import os

    # Generate unique salt
    salt = os.urandom(16)

    # Derive key with unique salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
    cipher = Fernet(key)

    # Encrypt
    encrypted_bytes = cipher.encrypt(plaintext.encode())

    # Combine salt + encrypted data
    combined = salt + encrypted_bytes

    # Encode as base64
    return base64.urlsafe_b64encode(combined).decode('utf-8')


async def migrate_encryption():
    """Migrate all existing encrypted API keys to new format"""
    print("🔐 Starting encryption migration...")
    print(f"Using SECRET_KEY: {settings.SECRET_KEY[:10]}...")

    async with AsyncSessionLocal() as db:
        # Fetch all providers
        result = await db.execute(select(LLMProvider))
        providers = result.scalars().all()

        if not providers:
            print("ℹ️  No providers found. Nothing to migrate.")
            return

        print(f"Found {len(providers)} provider(s) to migrate\n")

        for provider in providers:
            print(f"Migrating: {provider.name} ({provider.id})")

            try:
                # Decrypt with OLD method
                old_encrypted = provider.api_key_encrypted
                plaintext_key = old_decrypt(old_encrypted, settings.SECRET_KEY)
                print(f"  ✓ Decrypted with old method (key: {plaintext_key[:8]}...)")

                # Re-encrypt with NEW method
                new_encrypted = new_encrypt(plaintext_key, settings.SECRET_KEY)
                print(f"  ✓ Re-encrypted with new method")

                # Update in database
                provider.api_key_encrypted = new_encrypted

                print(f"  ✓ Updated in database\n")

            except Exception as e:
                print(f"  ✗ ERROR migrating {provider.name}: {e}\n")
                raise

        # Commit all changes
        await db.commit()
        print("✅ Migration completed successfully!")
        print(f"   {len(providers)} provider(s) migrated")


if __name__ == "__main__":
    try:
        asyncio.run(migrate_encryption())
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        sys.exit(1)
