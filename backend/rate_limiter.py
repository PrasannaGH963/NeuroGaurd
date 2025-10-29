"""
Rate limiting system using sliding window algorithm.
Tracks requests per session and enforces limits.
"""
import time
from typing import Dict, Optional, Tuple
from collections import deque
from config import get_config


class RateLimiter:
    """
    Implements sliding window rate limiting.
    Tracks requests per session with minute and hour limits.
    """
    
    def __init__(self):
        """Initialize rate limiter with configuration."""
        self.config = get_config()
        # session_id -> deque of timestamps
        self.minute_requests: Dict[str, deque] = {}
        self.hour_requests: Dict[str, deque] = {}
    
    def check_rate_limit(self, session_id: str) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Check if request is within rate limits.
        
        Args:
            session_id: User session identifier
            
        Returns:
            Tuple of (allowed: bool, message: Optional[str], retry_after: Optional[int])
            retry_after is seconds until limit resets
        """
        current_time = time.time()
        
        # Initialize deques if needed
        if session_id not in self.minute_requests:
            self.minute_requests[session_id] = deque()
        if session_id not in self.hour_requests:
            self.hour_requests[session_id] = deque()
        
        minute_deque = self.minute_requests[session_id]
        hour_deque = self.hour_requests[session_id]
        
        # Clean old entries (outside window)
        minute_cutoff = current_time - 60  # 1 minute ago
        hour_cutoff = current_time - 3600  # 1 hour ago
        
        while minute_deque and minute_deque[0] < minute_cutoff:
            minute_deque.popleft()
        
        while hour_deque and hour_deque[0] < hour_cutoff:
            hour_deque.popleft()
        
        # Check minute limit
        if len(minute_deque) >= self.config.rate_limit_per_minute:
            oldest_in_window = minute_deque[0]
            retry_after = int(60 - (current_time - oldest_in_window)) + 1
            return False, f"Rate limit exceeded: {self.config.rate_limit_per_minute} requests per minute", retry_after
        
        # Check hour limit
        if len(hour_deque) >= self.config.rate_limit_per_hour:
            oldest_in_window = hour_deque[0]
            retry_after = int(3600 - (current_time - oldest_in_window)) + 1
            return False, f"Rate limit exceeded: {self.config.rate_limit_per_hour} requests per hour", retry_after
        
        # Add current request
        minute_deque.append(current_time)
        hour_deque.append(current_time)
        
        return True, None, None
    
    def get_rate_limit_status(self, session_id: str) -> Dict[str, any]:
        """
        Get current rate limit status for a session.
        
        Args:
            session_id: User session identifier
            
        Returns:
            Dict with rate limit statistics
        """
        current_time = time.time()
        
        minute_count = 0
        hour_count = 0
        
        if session_id in self.minute_requests:
            minute_deque = self.minute_requests[session_id]
            minute_cutoff = current_time - 60
            minute_count = sum(1 for t in minute_deque if t >= minute_cutoff)
        
        if session_id in self.hour_requests:
            hour_deque = self.hour_requests[session_id]
            hour_cutoff = current_time - 3600
            hour_count = sum(1 for t in hour_deque if t >= hour_cutoff)
        
        return {
            'minute_requests': minute_count,
            'minute_limit': self.config.rate_limit_per_minute,
            'hour_requests': hour_count,
            'hour_limit': self.config.rate_limit_per_hour,
            'minute_remaining': self.config.rate_limit_per_minute - minute_count,
            'hour_remaining': self.config.rate_limit_per_hour - hour_count
        }

