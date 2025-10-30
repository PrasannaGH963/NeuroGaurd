"""
Rate limiting system using sliding window algorithm.
Tracks requests per session and enforces limits.
"""
import time
from typing import Dict, Optional, Tuple
from collections import deque
from threading import Timer, Lock
from config import get_config

class RateLimiter:
    """
    Implements sliding window rate limiting.
    Tracks requests per session with minute and hour limits.
    Periodically cleans up old sessions to prevent memory leak.
    """

    def __init__(self):
        self.config = get_config()
        self.minute_requests: Dict[str, deque] = {}
        self.hour_requests: Dict[str, deque] = {}
        self.inactive_threshold = 86400  # 24 hours in seconds
        self.cleanup_interval = 3600     # 1 hour in seconds
        self._lock = Lock()
        self._cleanup_timer: Optional[Timer] = None
        self._start_cleanup_timer()

    def _start_cleanup_timer(self):
        """Start periodic cleanup of inactive sessions."""
        # Schedule the first run immediately
        self._cleanup_inactive_sessions()
        # Then reschedule
        self._cleanup_timer = Timer(self.cleanup_interval, self._start_cleanup_timer)
        self._cleanup_timer.daemon = True
        self._cleanup_timer.start()

    def _cleanup_inactive_sessions(self) -> int:
        """Remove sessions with no activity >24h. Returns number cleaned."""
        with self._lock:
            current_time = time.time()
            inactive_sessions = []
            # Only look through hour_requests for activity
            for session_id in list(self.hour_requests.keys()):
                dq = self.hour_requests.get(session_id)
                if dq and dq:
                    last_request = dq[-1]
                    if current_time - last_request > self.inactive_threshold:
                        inactive_sessions.append(session_id)
            for session_id in inactive_sessions:
                if session_id in self.minute_requests:
                    del self.minute_requests[session_id]
                if session_id in self.hour_requests:
                    del self.hour_requests[session_id]
            return len(inactive_sessions)

    def manual_cleanup(self) -> int:
        """Manual trigger for session cleanup. Returns cleaned count."""
        return self._cleanup_inactive_sessions()

    def get_memory_stats(self) -> Dict[str, int]:
        """Get current memory usage statistics for rate limiter."""
        with self._lock:
            total_sessions = len(self.hour_requests)
            minute_entries = sum(len(q) for q in self.minute_requests.values())
            hour_entries = sum(len(q) for q in self.hour_requests.values())
            return {
                'total_sessions': total_sessions,
                'minute_entries': minute_entries,
                'hour_entries': hour_entries
            }

    # Existing methods, UNCHANGED, but wrapped in thread-safe block for cleanup

    def check_rate_limit(self, session_id: str) -> Tuple[bool, Optional[str], Optional[int]]:
        current_time = time.time()
        with self._lock:
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
        current_time = time.time()
        with self._lock:
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

