"""
Security Module
Criptografia de senhas e tokens
"""

from cryptography.fernet import Fernet
import os
import base64
import logging

logger = logging.getLogger(__name__)

# Encryption key para senhas de ES servers
# IMPORTANTE: Em produção, use variável de ambiente ou AWS Secrets Manager
ENCRYPTION_KEY = os.getenv(
    "ENCRYPTION_KEY",
    "dashboard-ai-encryption-key-2024-change-in-production-please"
)


def _get_fernet_key() -> bytes:
    """
    Gera chave Fernet a partir da ENCRYPTION_KEY
    Fernet precisa de uma chave de 32 bytes base64-encoded
    """
    # Converter string para 32 bytes
    key_bytes = ENCRYPTION_KEY.encode('utf-8')

    # Garantir 32 bytes (padding ou truncate)
    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b'0')
    else:
        key_bytes = key_bytes[:32]

    # Encode em base64 para Fernet
    return base64.urlsafe_b64encode(key_bytes)


# Inicializar Fernet cipher
_fernet = Fernet(_get_fernet_key())


def encrypt_password(plain_password: str) -> str:
    """
    Criptografa senha usando Fernet (AES 128 simétrica)

    Args:
        plain_password: Senha em texto plano

    Returns:
        Senha criptografada (base64 string)

    Example:
        >>> encrypted = encrypt_password("my_secret_pass")
        >>> print(encrypted)
        'gAAAAABk...'
    """
    if not plain_password:
        return ""

    try:
        encrypted_bytes = _fernet.encrypt(plain_password.encode('utf-8'))
        return encrypted_bytes.decode('utf-8')
    except Exception as e:
        logger.error(f"❌ Error encrypting password: {e}")
        raise


def decrypt_password(encrypted_password: str) -> str:
    """
    Descriptografa senha usando Fernet

    Args:
        encrypted_password: Senha criptografada (base64 string)

    Returns:
        Senha em texto plano

    Example:
        >>> plain = decrypt_password(encrypted)
        >>> print(plain)
        'my_secret_pass'
    """
    if not encrypted_password:
        return ""

    try:
        decrypted_bytes = _fernet.decrypt(encrypted_password.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        logger.error(f"❌ Error decrypting password: {e}")
        raise


def generate_new_encryption_key() -> str:
    """
    Gera nova chave de criptografia Fernet
    Use isso para gerar ENCRYPTION_KEY em produção

    Returns:
        Chave base64-encoded para uso em variável de ambiente

    Example:
        >>> new_key = generate_new_encryption_key()
        >>> print(f"ENCRYPTION_KEY={new_key}")
        ENCRYPTION_KEY=wO9uXCPMxVp4...
    """
    return Fernet.generate_key().decode('utf-8')


# TODO: Funções para bcrypt (User passwords)
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """
    Hash de senha usando bcrypt (para User model)

    Args:
        password: Senha em texto plano

    Returns:
        Hash bcrypt
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica se senha bate com hash bcrypt

    Args:
        plain_password: Senha fornecida pelo usuário
        hashed_password: Hash armazenado no banco

    Returns:
        True se senha correta, False caso contrário
    """
    return pwd_context.verify(plain_password, hashed_password)


if __name__ == "__main__":
    # Exemplo de uso
    print("\n=== Teste de Criptografia ===\n")

    # Gerar nova chave
    print("1. Gerar nova chave:")
    new_key = generate_new_encryption_key()
    print(f"   ENCRYPTION_KEY={new_key}\n")

    # Testar criptografia
    print("2. Testar criptografia de senha:")
    test_password = "minha_senha_super_secreta_123"
    encrypted = encrypt_password(test_password)
    print(f"   Original:  {test_password}")
    print(f"   Encrypted: {encrypted}")

    decrypted = decrypt_password(encrypted)
    print(f"   Decrypted: {decrypted}")
    print(f"   Match: {test_password == decrypted}\n")

    # Testar bcrypt
    print("3. Testar hash bcrypt (para users):")
    user_password = "user_password_123"
    hashed = hash_password(user_password)
    print(f"   Password: {user_password}")
    print(f"   Hash:     {hashed}")
    print(f"   Verify:   {verify_password(user_password, hashed)}")
    print(f"   Wrong:    {verify_password('wrong_pass', hashed)}\n")
