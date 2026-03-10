"""
Error handling example — handle all SDK error types gracefully.

Usage:
    CLAWGUARD_API_KEY=cgs_your_key python examples/error_handling.py
"""

import os
import sys

from clawguard_shield import Shield
from clawguard_shield.client import (
    AuthenticationError,
    RateLimitError,
    ShieldError,
    ValidationError,
)


def safe_scan(shield: Shield, text: str):
    """Scan with full error handling — returns None on failure."""
    try:
        return shield.scan(text)
    except AuthenticationError as e:
        print(f"Auth failed — check your CLAWGUARD_API_KEY")
        print(f"  Status: {e.status_code}, Type: {e.error_type}")
        return None
    except RateLimitError as e:
        print(f"Rate limited — upgrade at https://prompttools.co/pricing")
        return None
    except ValidationError as e:
        print(f"Validation error: {e}")
        return None
    except ShieldError as e:
        print(f"Shield API error: {e} ({e.status_code})")
        return None


def main():
    # 1. Constructor validates API key format
    try:
        Shield("invalid_key")
    except ValueError as e:
        print(f"Constructor validation: {e}")

    # 2. Normal usage with error handling
    api_key = os.environ.get("CLAWGUARD_API_KEY")
    if not api_key:
        print("Set CLAWGUARD_API_KEY environment variable", file=sys.stderr)
        sys.exit(1)

    shield = Shield(api_key)

    # Health check (no auth required) — good for connection testing
    try:
        health = shield.health()
        print(f"\nAPI healthy: {health['status']}, {health['patterns_count']} patterns")
    except Exception as e:
        print(f"Cannot reach Shield API: {e}")
        sys.exit(1)

    # Scan with full error handling
    result = safe_scan(shield, "Hello, how are you?")
    if result:
        print(f"\nScan result: clean={result.clean}, severity={result.severity}")

    # Check usage to avoid rate limits proactively
    try:
        usage = shield.usage()
        print(f"\nUsage: {usage.today_used}/{usage.daily_limit} scans ({usage.tier_name})")
        if usage.today_remaining < 10:
            print("Warning: Running low on daily scans!")
    except ShieldError as e:
        print(f"Could not fetch usage: {e}")


if __name__ == "__main__":
    main()
