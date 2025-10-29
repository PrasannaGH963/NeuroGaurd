"""
Tests for audit logging system.
"""
import pytest
from audit_logger import AuditLogger


class TestAuditLogging:
    """Test audit logging functionality."""
    
    def test_log_interaction(self):
        """Test logging an interaction."""
        logger = AuditLogger()
        session_id = "test_session"
        
        layers = [
            {"layer": "Prompt Injection", "result": "pass"},
            {"layer": "Content Safety", "result": "pass"},
        ]
        
        log_id = logger.log_interaction(
            session_id=session_id,
            trust_score=85,
            trust_level="green",
            layers=layers,
            action="allow",
            prompt="test prompt",
            response="test response",
            provider="openai"
        )
        
        assert log_id is not None
        assert len(logger.logs) == 1
        assert logger.logs[0]['session_id'] == session_id
        assert logger.logs[0]['trust_score'] == 85
        assert 'current_hash' in logger.logs[0]
        assert 'previous_hash' in logger.logs[0]
    
    def test_chain_integrity(self):
        """Test hash chain integrity."""
        logger = AuditLogger()
        
        # Add multiple logs
        for i in range(5):
            logger.log_interaction(
                session_id=f"session_{i}",
                trust_score=50 + i,
                trust_level="yellow",
                layers=[],
                action="allow",
                prompt=f"prompt {i}",
                response=f"response {i}"
            )
        
        # Verify chain
        is_valid, errors = logger.verify_chain()
        assert is_valid, f"Chain verification failed: {errors}"
        assert len(errors) == 0
    
    def test_statistics(self):
        """Test statistics calculation."""
        logger = AuditLogger()
        
        # Add various interactions
        logger.log_interaction(
            session_id="s1",
            trust_score=90,
            trust_level="green",
            layers=[],
            action="allow",
            prompt="test",
            response="test"
        )
        
        logger.log_interaction(
            session_id="s2",
            trust_score=30,
            trust_level="red",
            layers=[],
            action="block",
            prompt="malicious",
            response=None
        )
        
        stats = logger.get_statistics()
        
        assert stats['total_interactions'] == 2
        assert stats['allowed_count'] == 1
        assert stats['blocked_count'] == 1
        assert stats['blocked_percentage'] == 50.0

