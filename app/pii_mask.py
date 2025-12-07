"""
PII Masking Utilities for GDPR Compliance

Provides functions to mask sensitive information in logs.
"""

import re
from typing import Optional


def mask_email(email: Optional[str], show_chars: int = 3) -> str:
    """
    Mask email address for logging (GDPR compliant).
    
    Examples:
        test@gmail.com → tes***@g***.com
        john.doe@example.com → joh***@e***.com
        a@b.co → a***@b***.co
    
    Args:
        email: Email address to mask
        show_chars: Number of characters to show from username (default: 3)
    
    Returns:
        Masked email string
    """
    if not email or not isinstance(email, str):
        return "***@***.***"
    
    try:
        if "@" not in email:
            return "***invalid***"
        
        username, domain = email.rsplit("@", 1)
        
        # Mask username (show first N chars)
        if len(username) <= show_chars:
            masked_username = username[0] + "***"
        else:
            masked_username = username[:show_chars] + "***"
        
        # Mask domain (show first char and TLD)
        if "." in domain:
            domain_parts = domain.split(".")
            masked_domain_name = domain_parts[0][0] + "***"
            tld = domain_parts[-1]
            masked_domain = f"{masked_domain_name}.{tld}"
        else:
            masked_domain = domain[0] + "***"
        
        return f"{masked_username}@{masked_domain}"
    
    except Exception:
        return "***@***.***"


def mask_password(password: Optional[str]) -> str:
    """
    Completely mask password (never log actual password).
    
    Args:
        password: Password to mask
    
    Returns:
        Always returns "[REDACTED]"
    """
    return "[REDACTED]"


def mask_user_id(user_id: Optional[str], show_chars: int = 8) -> str:
    """
    Mask user ID showing only first N characters.
    
    Args:
        user_id: User ID (UUID) to mask
        show_chars: Number of characters to show (default: 8)
    
    Returns:
        Masked user ID
    """
    if not user_id or not isinstance(user_id, str):
        return "***"
    
    if len(user_id) <= show_chars:
        return user_id
    
    return f"{user_id[:show_chars]}***"


def sanitize_request_body(body: str) -> str:
    """
    Sanitize request body by masking sensitive fields.
    
    Masks: password, email, api_key, token, secret
    
    Args:
        body: Request body string
    
    Returns:
        Sanitized body string
    """
    if not body:
        return ""
    
    # Mask passwords
    body = re.sub(
        r'(["\']?password["\']?\s*[:=]\s*["\']?)([^"\'&\s]+)',
        r'\1[REDACTED]',
        body,
        flags=re.IGNORECASE
    )
    
    # Mask emails
    body = re.sub(
        r'(["\']?(?:email|username)["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        lambda m: m.group(1) + mask_email(m.group(2)),
        body,
        flags=re.IGNORECASE
    )
    
    # Mask API keys
    body = re.sub(
        r'(["\']?api[_-]?key["\']?\s*[:=]\s*["\']?)([^"\'&\s]+)',
        r'\1[REDACTED]',
        body,
        flags=re.IGNORECASE
    )
    
    # Mask tokens
    body = re.sub(
        r'(["\']?(?:token|secret)["\']?\s*[:=]\s*["\']?)([^"\'&\s]+)',
        r'\1[REDACTED]',
        body,
        flags=re.IGNORECASE
    )
    
    return body
