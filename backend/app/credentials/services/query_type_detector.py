"""
Query Type Detector - Detecta automaticamente o tipo de consulta

Suporta detecção de:
- Email: usuario@dominio.com
- CPF: 000.000.000-00 ou 00000000000
- CNPJ: 00.000.000/0000-00 ou 00000000000000
- Telefone: +55 (51) 99999-9999, (51) 99999-9999, 51999999999
- IP: 192.168.1.1, 2001:0db8:85a3::8a2e:0370:7334
- Domínio: exemplo.com.br
- Username: @usuario ou strings simples
"""

import re
import logging
from typing import Tuple

logger = logging.getLogger(__name__)


class QueryTypeDetector:
    """Detecta automaticamente o tipo de consulta baseado em padrões regex"""

    # Padrões regex para cada tipo
    PATTERNS = {
        # Email: usuario@dominio.com
        "email": re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            re.IGNORECASE
        ),

        # CPF: 000.000.000-00 ou 00000000000
        "cpf": re.compile(
            r'^(\d{3}\.?\d{3}\.?\d{3}-?\d{2})$'
        ),

        # CNPJ: 00.000.000/0000-00 ou 00000000000000
        "cnpj": re.compile(
            r'^(\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2})$'
        ),

        # Telefone brasileiro: vários formatos
        # +55 (51) 99999-9999, (51) 99999-9999, 51999999999, etc
        "phone": re.compile(
            r'^(\+?55)?[\s.-]?\(?(\d{2})\)?[\s.-]?(\d{4,5})[\s.-]?(\d{4})$'
        ),

        # IPv4: 192.168.1.1
        "ipv4": re.compile(
            r'^(\d{1,3}\.){3}\d{1,3}$'
        ),

        # IPv6: 2001:0db8:85a3::8a2e:0370:7334
        "ipv6": re.compile(
            r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        ),

        # Domínio: exemplo.com, exemplo.com.br
        "domain": re.compile(
            r'^(?!-)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
        ),

        # Username do Telegram: @usuario
        "telegram_username": re.compile(
            r'^@[a-zA-Z0-9_]{5,32}$'
        ),
    }

    # Ordem de prioridade para verificação
    # (mais específicos primeiro)
    CHECK_ORDER = [
        "email",
        "cpf",
        "cnpj",
        "phone",
        "ipv4",
        "ipv6",
        "telegram_username",
        "domain",
    ]

    @classmethod
    def detect(cls, value: str) -> Tuple[str, str]:
        """
        Detecta o tipo de consulta e normaliza o valor.

        Args:
            value: String de entrada do usuário

        Returns:
            Tuple (tipo_detectado, valor_normalizado)
            Se não detectar, retorna ("username", valor_original)
        """
        # Remove espaços extras
        value = value.strip()

        if not value:
            return ("unknown", value)

        # Tenta cada padrão na ordem de prioridade
        for query_type in cls.CHECK_ORDER:
            pattern = cls.PATTERNS[query_type]
            if pattern.match(value):
                normalized = cls._normalize(query_type, value)
                logger.info(f"🎯 Tipo detectado: {query_type} para '{value[:20]}...'")
                return (query_type, normalized)

        # Se não detectou nenhum padrão específico, assume username
        logger.info(f"🎯 Tipo detectado: username (default) para '{value[:20]}...'")
        return ("username", value)

    @classmethod
    def _normalize(cls, query_type: str, value: str) -> str:
        """
        Normaliza o valor para o formato esperado pelo bot.

        Args:
            query_type: Tipo detectado
            value: Valor original

        Returns:
            Valor normalizado
        """
        if query_type == "cpf":
            # Remove formatação: 000.000.000-00 -> 00000000000
            return re.sub(r'[.\-]', '', value)

        elif query_type == "cnpj":
            # Remove formatação: 00.000.000/0000-00 -> 00000000000000
            return re.sub(r'[.\-/]', '', value)

        elif query_type == "phone":
            # Remove formatação, mantém só números
            # +55 (51) 99999-9999 -> 5551999999999
            digits = re.sub(r'\D', '', value)
            # Se não começar com 55, adiciona
            if not digits.startswith('55') and len(digits) <= 11:
                digits = '55' + digits
            return digits

        elif query_type == "email":
            # Lowercase para emails
            return value.lower()

        elif query_type == "domain":
            # Lowercase e remove www.
            value = value.lower()
            if value.startswith('www.'):
                value = value[4:]
            return value

        elif query_type == "telegram_username":
            # Remove @ se presente
            return value.lstrip('@')

        elif query_type in ("ipv4", "ipv6"):
            # IP retorna como está
            return value

        return value

    @classmethod
    def get_display_type(cls, query_type: str) -> str:
        """
        Retorna o nome amigável do tipo para exibição.

        Args:
            query_type: Tipo interno

        Returns:
            Nome para exibição
        """
        display_names = {
            "email": "Email",
            "cpf": "CPF",
            "cnpj": "CNPJ",
            "phone": "Telefone",
            "ipv4": "IP (v4)",
            "ipv6": "IP (v6)",
            "domain": "Domínio",
            "telegram_username": "Username Telegram",
            "username": "Username",
            "unknown": "Desconhecido"
        }
        return display_names.get(query_type, query_type.title())

    @classmethod
    def validate_cpf(cls, cpf: str) -> bool:
        """Valida se o CPF é válido (opcional)"""
        cpf = re.sub(r'\D', '', cpf)
        if len(cpf) != 11:
            return False
        if cpf == cpf[0] * 11:
            return False
        # Validação dos dígitos verificadores
        # ... (simplificado por agora)
        return True

    @classmethod
    def validate_cnpj(cls, cnpj: str) -> bool:
        """Valida se o CNPJ é válido (opcional)"""
        cnpj = re.sub(r'\D', '', cnpj)
        if len(cnpj) != 14:
            return False
        if cnpj == cnpj[0] * 14:
            return False
        return True


# Função de conveniência
def detect_query_type(value: str) -> Tuple[str, str]:
    """
    Detecta automaticamente o tipo de consulta.

    Args:
        value: Valor de entrada do usuário

    Returns:
        Tuple (tipo_detectado, valor_normalizado)
    """
    return QueryTypeDetector.detect(value)
