"""
Rate Limit Tiers Configuration
"""

from enum import Enum
from pydantic import BaseModel
from typing import Dict

class UserTier(str, Enum):
    FREE = "free"
    PRO = "premium"
    ENTERPRISE = "enterprise"

class RateLimitConfig(BaseModel):
    requests_per_minute: int
    requests_per_day: int
    burst_allowance: int  # Requests per second allowed

TIER_CONFIGS: Dict[UserTier, RateLimitConfig] = {
    UserTier.FREE: RateLimitConfig(
        requests_per_minute=10,
        requests_per_day=1000,
        burst_allowance=2
    ),
    UserTier.PRO: RateLimitConfig(
        requests_per_minute=100,
        requests_per_day=100000,
        burst_allowance=20
    ),
    UserTier.ENTERPRISE: RateLimitConfig(
        requests_per_minute=1000,
        requests_per_day=1000000,
        burst_allowance=100
    )
}

def get_user_tier(api_key: str) -> UserTier:
    """
    Determine user tier based on API key.
    
    In a real app, this would query a database or cache.
    For now, we use key prefixes.
    """
    if not api_key:
        return UserTier.FREE
        
    if api_key.startswith("msp_live_"):
        return UserTier.PRO
    elif api_key.startswith("msp_ent_"):
        return UserTier.ENTERPRISE
    elif api_key.startswith("msp_test_"):
        # Test keys get Pro limits for development ease
        return UserTier.PRO
        
    return UserTier.FREE
