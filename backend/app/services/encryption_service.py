"""
Encryption Service
Handles encryption/decryption of sensitive data like API keys
Uses Fernet encryption with unique salt per record for enhanced security
"""

import os
import logging
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)


class EncryptionService:
    """Service for encrypting/decrypting sensitive data with unique salt per record"""

    def __init__(self, secret_key: Optional[str] = None):
        """
        Initialize encryption service

        Args:
            secret_key: Secret key for encryption (uses SECRET_KEY from env if not provided)
        """
        from app.core.config import settings

        # Use provided key or fall back to settings
        self._master_key = secret_key or settings.SECRET_KEY

        if not self._master_key:
            raise ValueError("SECRET_KEY must be set for encryption")

        logger.info("✅ Encryption service initialized with dynamic salt support")

    def _derive_key(self, salt: bytes) -> bytes:
        """
        Derive a Fernet-compatible key from master key with unique salt

        Args:
            salt: Unique salt for this encryption

        Returns:
            32-byte Fernet key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self._master_key.encode()))
        return key

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a string with unique salt

        Format: base64(salt + encrypted_data)
        - First 16 bytes: unique salt
        - Remaining bytes: Fernet encrypted data

        Args:
            plaintext: String to encrypt

        Returns:
            Encrypted string (base64 encoded with embedded salt)
        """
        if not plaintext:
            return ""

        # Generate unique salt for this encryption
        salt = os.urandom(16)

        # Derive key with unique salt
        fernet_key = self._derive_key(salt)
        cipher = Fernet(fernet_key)

        # Encrypt the data
        encrypted_bytes = cipher.encrypt(plaintext.encode())

        # Combine salt + encrypted data
        combined = salt + encrypted_bytes

        # Encode everything as base64
        return base64.urlsafe_b64encode(combined).decode('utf-8')

    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypt a string encrypted with unique salt

        Args:
            encrypted_text: Encrypted string (base64 encoded with embedded salt)

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If decryption fails
        """
        if not encrypted_text:
            return ""

        try:
            # Decode base64
            combined = base64.urlsafe_b64decode(encrypted_text.encode())

            # Extract salt (first 16 bytes) and encrypted data (rest)
            salt = combined[:16]
            encrypted_bytes = combined[16:]

            # Derive key with extracted salt
            fernet_key = self._derive_key(salt)
            cipher = Fernet(fernet_key)

            # Decrypt
            decrypted_bytes = cipher.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')

        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError("Failed to decrypt data. Key may be invalid or data corrupted.")


# Singleton instance
_encryption_service: Optional[EncryptionService] = None


def get_encryption_service() -> EncryptionService:
    """Get singleton instance of encryption service"""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = EncryptionService()
    return _encryption_service
