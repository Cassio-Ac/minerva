"""
Unified IOC Normalizer

Normalizes IOC values for consistent storage, deduplication and lookup.
Handles defanging, case normalization, and type-specific processing.
"""

import re
import hashlib
import ipaddress
from urllib.parse import urlparse
from typing import Optional, Tuple


class IOCNormalizer:
    """Normalizes IOC values for consistent storage and lookup"""

    # Defang patterns
    DEFANG_PATTERNS = [
        (r'hxxp', 'http'),
        (r'hXXp', 'http'),
        (r'\[\.\]', '.'),
        (r'\[dot\]', '.'),
        (r'\[\:\]', ':'),
        (r'\[:\]', ':'),
        (r'\[@\]', '@'),
        (r'\[at\]', '@'),
    ]

    # IOC type detection patterns
    PATTERNS = {
        'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
        'sha512': re.compile(r'^[a-fA-F0-9]{128}$'),
        'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        'url': re.compile(r'^https?://', re.IGNORECASE),
        'ipv4': re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'),
        'ipv6': re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/\d{1,3})?$'),
        'domain': re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'),
    }

    def normalize(self, value: str, ioc_type: Optional[str] = None) -> str:
        """
        Normalize IOC value based on type.

        Args:
            value: Raw IOC value
            ioc_type: Optional type hint (ip, domain, url, hash, email)

        Returns:
            Normalized IOC value
        """
        if not value:
            return ""

        # Clean whitespace
        value = value.strip()

        # Refang if defanged
        value = self._refang(value)

        # Get normalizer for type
        if ioc_type:
            normalizers = {
                'ip': self.normalize_ip,
                'ipv4': self.normalize_ip,
                'ipv6': self.normalize_ip,
                'domain': self.normalize_domain,
                'hostname': self.normalize_domain,
                'url': self.normalize_url,
                'hash': self.normalize_hash,
                'md5': self.normalize_hash,
                'sha1': self.normalize_hash,
                'sha256': self.normalize_hash,
                'sha512': self.normalize_hash,
                'email': self.normalize_email,
            }
            normalizer = normalizers.get(ioc_type.lower(), self.normalize_generic)
            return normalizer(value)

        # Auto-detect type and normalize
        detected_type = self.detect_type(value)
        return self.normalize(value, detected_type)

    def normalize_and_hash(self, value: str, ioc_type: Optional[str] = None) -> Tuple[str, str]:
        """
        Normalize IOC and compute hash for deduplication.

        Returns:
            Tuple of (normalized_value, sha256_hash)
        """
        normalized = self.normalize(value, ioc_type)
        hash_value = self.compute_hash(normalized)
        return normalized, hash_value

    def compute_hash(self, normalized_value: str) -> str:
        """Compute SHA256 hash for deduplication"""
        return hashlib.sha256(normalized_value.lower().encode('utf-8')).hexdigest()

    def detect_type(self, value: str) -> str:
        """
        Auto-detect IOC type from value.

        Returns:
            Detected type: ip, domain, url, hash, email, or other
        """
        value = value.strip()

        # Check hashes first (most specific)
        if self.PATTERNS['md5'].match(value):
            return 'hash'
        if self.PATTERNS['sha1'].match(value):
            return 'hash'
        if self.PATTERNS['sha256'].match(value):
            return 'hash'
        if self.PATTERNS['sha512'].match(value):
            return 'hash'

        # Check email
        if self.PATTERNS['email'].match(value):
            return 'email'

        # Check URL
        if self.PATTERNS['url'].match(value):
            return 'url'

        # Check IP addresses
        # Remove port if present for detection
        check_value = value.split(':')[0] if ':' in value and not value.startswith('[') else value
        check_value = check_value.split('/')[0]  # Remove CIDR

        try:
            ipaddress.ip_address(check_value)
            return 'ip'
        except ValueError:
            pass

        # Check domain (after removing potential port)
        if self.PATTERNS['domain'].match(check_value):
            return 'domain'

        return 'other'

    def get_hash_subtype(self, value: str) -> Optional[str]:
        """Determine specific hash type (md5, sha1, sha256, sha512)"""
        value = value.strip().lower()

        if self.PATTERNS['md5'].match(value):
            return 'md5'
        if self.PATTERNS['sha1'].match(value):
            return 'sha1'
        if self.PATTERNS['sha256'].match(value):
            return 'sha256'
        if self.PATTERNS['sha512'].match(value):
            return 'sha512'

        return None

    def normalize_ip(self, value: str) -> str:
        """
        Normalize IP address.
        - Removes port if present
        - Validates and normalizes format
        - Preserves CIDR notation
        """
        value = value.strip()

        # Extract CIDR if present
        cidr = None
        if '/' in value:
            parts = value.split('/')
            value = parts[0]
            cidr = parts[1]

        # Remove port if present (IPv4 style)
        if ':' in value and not value.startswith('['):
            # Could be IPv4:port or IPv6
            parts = value.rsplit(':', 1)
            if parts[1].isdigit():  # It's a port
                value = parts[0]

        # Handle IPv6 with brackets [::1]:port
        if value.startswith('[') and ']:' in value:
            value = value.split(']:')[0][1:]
        elif value.startswith('[') and value.endswith(']'):
            value = value[1:-1]

        try:
            ip = ipaddress.ip_address(value)
            normalized = str(ip)

            # Add back CIDR if present
            if cidr:
                normalized = f"{normalized}/{cidr}"

            return normalized
        except ValueError:
            return value.lower()

    def normalize_domain(self, value: str) -> str:
        """
        Normalize domain name.
        - Lowercase
        - Remove protocol if present
        - Remove trailing dot
        - Remove www prefix for consistency
        - Remove port if present
        """
        value = value.lower().strip()

        # Remove protocol if present
        if '://' in value:
            value = urlparse(value).netloc or value

        # Remove port if present
        if ':' in value:
            value = value.split(':')[0]

        # Remove trailing dot (FQDN format)
        value = value.rstrip('.')

        # Remove www prefix for better deduplication
        if value.startswith('www.'):
            value = value[4:]

        return value

    def normalize_url(self, value: str) -> str:
        """
        Normalize URL.
        - Refang
        - Lowercase scheme and domain
        - Preserve path case
        - Remove default ports
        - Remove trailing slash from path (optional)
        """
        value = value.strip()

        # Ensure scheme
        if not value.startswith(('http://', 'https://')):
            value = 'http://' + value

        try:
            parsed = urlparse(value)

            # Normalize scheme and netloc
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()

            # Remove default ports
            if netloc.endswith(':80') and scheme == 'http':
                netloc = netloc[:-3]
            elif netloc.endswith(':443') and scheme == 'https':
                netloc = netloc[:-4]

            # Reconstruct URL
            path = parsed.path or '/'
            normalized = f"{scheme}://{netloc}{path}"

            if parsed.query:
                normalized += f"?{parsed.query}"
            if parsed.fragment:
                normalized += f"#{parsed.fragment}"

            return normalized
        except Exception:
            return value.lower()

    def normalize_hash(self, value: str) -> str:
        """Normalize hash value - just lowercase"""
        return value.strip().lower()

    def normalize_email(self, value: str) -> str:
        """Normalize email address - lowercase"""
        return value.strip().lower()

    def normalize_generic(self, value: str) -> str:
        """Generic normalization - trim and lowercase"""
        return value.strip().lower()

    def _refang(self, value: str) -> str:
        """Convert defanged IOC to normal format"""
        for pattern, replacement in self.DEFANG_PATTERNS:
            value = re.sub(pattern, replacement, value, flags=re.IGNORECASE)
        return value

    def is_valid_ioc(self, value: str, ioc_type: Optional[str] = None) -> bool:
        """
        Validate if value is a valid IOC of the specified type.

        Args:
            value: IOC value to validate
            ioc_type: Expected type (optional, will auto-detect if not provided)

        Returns:
            True if valid, False otherwise
        """
        if not value or not value.strip():
            return False

        value = self._refang(value.strip())
        detected = self.detect_type(value)

        if ioc_type:
            # Normalize type names
            type_map = {
                'ipv4': 'ip', 'ipv6': 'ip',
                'md5': 'hash', 'sha1': 'hash', 'sha256': 'hash', 'sha512': 'hash',
                'hostname': 'domain',
            }
            expected = type_map.get(ioc_type.lower(), ioc_type.lower())
            return detected == expected or detected != 'other'

        return detected != 'other'


# Singleton instance for convenience
_normalizer = None

def get_normalizer() -> IOCNormalizer:
    """Get singleton normalizer instance"""
    global _normalizer
    if _normalizer is None:
        _normalizer = IOCNormalizer()
    return _normalizer
