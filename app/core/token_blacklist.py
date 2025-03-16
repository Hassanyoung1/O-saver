from datetime import datetime, timedelta
from typing import Set

class TokenBlacklist:
    """
    Manages blacklisted JWT tokens to prevent reuse after logout.
    """
    _blacklist: Set[str] = set()

    @classmethod
    def add(cls, token: str, expiry_minutes: int = 30):
        """
        Adds a token to the blacklist.
        Args:
            token (str): The JWT token to be blacklisted.
            expiry_minutes (int): The time until the token is removed from the blacklist.
        """
        cls._blacklist.add(token)
        # Optionally, implement a cleanup mechanism to remove expired tokens.

    @classmethod
    def is_blacklisted(cls, token: str) -> bool:
        """
        Checks if a token is blacklisted.
        Args:
            token (str): The JWT token to check.
        Returns:
            bool: True if the token is blacklisted, False otherwise.
        """
        return token in cls._blacklist
