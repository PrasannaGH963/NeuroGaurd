"""
Trust scoring system for adaptive security decision making.
Tracks user history and calculates trust scores based on security layer results.
"""
from typing import Dict, List, Optional, Tuple
from collections import deque
from config import get_config


class TrustScoreEngine:
    """
    Calculates trust scores based on security layer results and user history.
    Maintains interaction history per session to adapt scoring.
    """
    
    def __init__(self):
        """Initialize trust score engine with configuration."""
        self.config = get_config()
        self.base_score = self.config.base_trust_score
        self.layer_weights = {
            'prompt_injection': self.config.layer_weight_prompt_injection,
            'content_safety': self.config.layer_weight_content_safety,
            'anomaly_detection': self.config.layer_weight_anomaly_detection,
            'context_integrity': self.config.layer_weight_context_integrity,
            'response_validation': self.config.layer_weight_response_validation,
        }
        # session_id -> deque(maxlen=max_user_history) of boolean (passed/failed)
        self.user_history: Dict[str, deque] = {}
    
    def calculate_score(
        self, 
        layer_results: Dict[str, bool], 
        session_id: str
    ) -> Dict[str, any]:
        """
        Calculate trust score based on layer results and user history.
        
        Args:
            layer_results: Dict mapping layer names to pass/fail (True/False)
            session_id: User session identifier
            
        Returns:
            Dict with 'score', 'level', 'action', and 'details'
        """
        # Start with base score
        score = float(self.base_score)
        
        # Apply layer results
        for layer_name, passed in layer_results.items():
            weight = self.layer_weights.get(layer_name, 0.0)
            if passed:
                # Add weighted percentage
                score += weight * 50  # Full weight adds 50 points (100% pass)
            else:
                # Subtract weighted percentage
                score -= weight * 50  # Full weight removes 50 points (100% fail)
        
        # Apply user history modifiers
        history_modifier = self._calculate_history_modifier(session_id)
        score += history_modifier
        
        # Clamp score to 0-100 range
        score = max(0, min(100, score))
        
        # Determine trust level and action
        level, action = self._get_trust_level_and_action(int(score))
        
        return {
            'score': int(score),
            'level': level,
            'action': action,
            'history_modifier': history_modifier,
            'base_score': self.base_score,
            'layer_contributions': {
                layer: ('+' if passed else '-') + str(weight * 50)
                for layer, passed in layer_results.items()
                for weight in [self.layer_weights.get(layer, 0.0)]
            }
        }
    
    def _calculate_history_modifier(self, session_id: str) -> float:
        """
        Calculate trust modifier based on user interaction history.
        
        Args:
            session_id: User session identifier
            
        Returns:
            Float modifier to apply to trust score
        """
        if session_id not in self.user_history:
            return 0.0
        
        history = list(self.user_history[session_id])
        if not history:
            return 0.0
        
        total = len(history)
        passed = sum(1 for h in history if h)
        clean_ratio = passed / total if total > 0 else 0.0
        
        modifier = 0.0
        
        # Boost for clean history
        if clean_ratio >= self.config.clean_history_threshold:
            modifier += self.config.trust_boost_clean_history
        
        # Penalty for suspicious patterns
        recent = history[-10:] if len(history) >= 10 else history
        alerts = sum(1 for h in recent if not h)
        if alerts >= self.config.suspicious_pattern_threshold:
            modifier += self.config.trust_penalty_suspicious
        
        return modifier
    
    def _get_trust_level_and_action(self, score: int) -> Tuple[str, str]:
        """
        Determine trust level and recommended action based on score.
        
        Args:
            score: Trust score (0-100)
            
        Returns:
            Tuple of (level, action)
        """
        if score >= self.config.trust_threshold_green:
            return 'green', 'allow'
        elif score >= self.config.trust_threshold_yellow:
            return 'yellow', 'warn'
        elif score >= self.config.trust_threshold_orange:
            return 'orange', 'restrict'
        else:
            return 'red', 'block'
    
    def update_history(self, session_id: str, passed: bool):
        """
        Update user interaction history.
        
        Args:
            session_id: User session identifier
            passed: Whether the interaction passed all security checks
        """
        if session_id not in self.user_history:
            self.user_history[session_id] = deque(maxlen=self.config.max_user_history)
        
        self.user_history[session_id].append(passed)
    
    def get_user_stats(self, session_id: str) -> Dict[str, any]:
        """
        Get statistics for a user session.
        
        Args:
            session_id: User session identifier
            
        Returns:
            Dict with user statistics
        """
        if session_id not in self.user_history or not self.user_history[session_id]:
            return {
                'total_interactions': 0,
                'passed_count': 0,
                'failed_count': 0,
                'clean_ratio': 0.0,
                'recent_alerts': 0
            }
        
        history = list(self.user_history[session_id])
        total = len(history)
        passed = sum(1 for h in history if h)
        recent_alerts = sum(1 for h in history[-10:] if not h)
        
        return {
            'total_interactions': total,
            'passed_count': passed,
            'failed_count': total - passed,
            'clean_ratio': passed / total if total > 0 else 0.0,
            'recent_alerts': recent_alerts
        }

