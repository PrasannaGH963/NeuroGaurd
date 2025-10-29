"""
Tests for trust scoring system.
"""
import pytest
from trust_scoring import TrustScoreEngine


class TestTrustScoring:
    """Test trust score calculation."""
    
    def test_perfect_score(self):
        """Test score with all layers passing."""
        engine = TrustScoreEngine()
        session_id = "test_session"
        
        layer_results = {
            'prompt_injection': True,
            'content_safety': True,
            'anomaly_detection': True,
            'context_integrity': True,
            'response_validation': True,
        }
        
        result = engine.calculate_score(layer_results, session_id)
        
        assert result['score'] >= 80  # Should be high
        assert result['level'] == 'green' or result['level'] == 'yellow'
        assert result['action'] in ['allow', 'warn']
    
    def test_failed_layers(self):
        """Test score with failed layers."""
        engine = TrustScoreEngine()
        session_id = "test_session_fail"
        
        layer_results = {
            'prompt_injection': False,  # Failed
            'content_safety': True,
            'anomaly_detection': True,
            'context_integrity': True,
            'response_validation': True,
        }
        
        result = engine.calculate_score(layer_results, session_id)
        
        assert result['score'] < 80  # Should be lower
        assert result['score'] >= 0  # Should be non-negative
        assert result['score'] <= 100  # Should be capped
    
    def test_user_history_boost(self):
        """Test user history boosting trust score."""
        engine = TrustScoreEngine()
        session_id = "clean_user"
        
        # Simulate clean history
        for _ in range(20):
            engine.update_history(session_id, True)
        
        layer_results = {
            'prompt_injection': True,
            'content_safety': True,
            'anomaly_detection': True,
            'context_integrity': True,
            'response_validation': True,
        }
        
        result = engine.calculate_score(layer_results, session_id)
        
        # Should have history boost
        assert result['score'] >= 80
    
    def test_user_history_penalty(self):
        """Test user history penalty."""
        engine = TrustScoreEngine()
        session_id = "suspicious_user"
        
        # Simulate suspicious history
        for _ in range(10):
            engine.update_history(session_id, False)  # All failures
        
        layer_results = {
            'prompt_injection': True,
            'content_safety': True,
            'anomaly_detection': True,
            'context_integrity': True,
            'response_validation': True,
        }
        
        result = engine.calculate_score(layer_results, session_id)
        
        # Should have penalty
        score_with_penalty = result['score']
        
        # Compare with new user
        new_session = "new_user"
        result_new = engine.calculate_score(layer_results, new_session)
        
        # Suspicious user should have lower or equal score
        assert score_with_penalty <= result_new['score']
    
    def test_user_stats(self):
        """Test user statistics retrieval."""
        engine = TrustScoreEngine()
        session_id = "stats_user"
        
        # Add some history
        engine.update_history(session_id, True)
        engine.update_history(session_id, True)
        engine.update_history(session_id, False)
        
        stats = engine.get_user_stats(session_id)
        
        assert stats['total_interactions'] == 3
        assert stats['passed_count'] == 2
        assert stats['failed_count'] == 1
        assert stats['clean_ratio'] == pytest.approx(2/3, rel=0.1)

