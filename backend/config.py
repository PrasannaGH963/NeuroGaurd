"""
Configuration management for NeuroGuard security system.
Supports environment variables and JSON configuration files.
Thread-safe singleton with validation.
"""
import json
import os
from dataclasses import dataclass, asdict
from typing import Optional, List
from threading import RLock

_config: Optional['SecurityConfig'] = None
_config_lock = RLock()  # Reentrant lock

@dataclass
class SecurityConfig:
    """Security configuration with all tunable parameters."""
    
    # Trust scoring
    base_trust_score: int = 50
    trust_threshold_green: int = 80
    trust_threshold_yellow: int = 60
    trust_threshold_orange: int = 40
    trust_boost_clean_history: int = 5
    trust_penalty_suspicious: int = -10
    clean_history_threshold: float = 0.90  # 90% clean interactions
    suspicious_pattern_threshold: int = 3  # 3 alerts in last 10
    
    # Layer weights
    layer_weight_prompt_injection: float = 0.25
    layer_weight_content_safety: float = 0.20
    layer_weight_anomaly_detection: float = 0.20
    layer_weight_context_integrity: float = 0.20
    layer_weight_response_validation: float = 0.15
    
    # Rate limiting
    rate_limit_per_minute: int = 20
    rate_limit_per_hour: int = 100
    
    # Anomaly detection
    max_prompt_length: int = 4000
    max_special_char_ratio: float = 0.2
    max_non_ascii_ratio: float = 0.05
    min_entropy: float = 2.5
    max_entropy: float = 5.5
    max_repetition_count: int = 3
    max_token_to_char_ratio: float = 0.8
    
    # ML detection
    ml_similarity_threshold: float = 0.75
    ml_confidence_threshold: float = 0.7
    ml_model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    
    # Response validation
    max_response_length: int = 5000
    
    # Audit logging
    max_logs_in_memory: int = 10000
    enable_chain_verification: bool = True
    
    # User history
    max_user_history: int = 100
    
    def to_dict(self) -> dict:
        """Convert config to dictionary."""
        return asdict(self)
    
    def save_to_file(self, filepath: str = "config.json"):
        """Save configuration to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    def validate(self) -> List[str]:
        """Validate configuration values, return list of issues."""
        errors = []
        if not (0 <= self.base_trust_score <= 100):
            errors.append("base_trust_score must be between 0 and 100")
        if self.trust_threshold_orange >= self.trust_threshold_yellow:
            errors.append("trust_threshold_orange must be less than trust_threshold_yellow")
        if self.trust_threshold_yellow >= self.trust_threshold_green:
            errors.append("trust_threshold_yellow must be less than trust_threshold_green")
        if self.rate_limit_per_minute <= 0 or self.rate_limit_per_hour <= 0:
            errors.append("Rate limits must be positive")
        if self.rate_limit_per_minute > self.rate_limit_per_hour:
            errors.append("per_minute limit cannot exceed per_hour limit")
        total_weight = sum([
            self.layer_weight_prompt_injection,
            self.layer_weight_content_safety,
            self.layer_weight_anomaly_detection,
            self.layer_weight_context_integrity,
            self.layer_weight_response_validation
        ])
        if not (0.95 <= total_weight <= 1.05):
            errors.append(f"Layer weights should sum to ~1.0 (currently {total_weight:.2f})")
        return errors
    
    @classmethod
    def load_from_file(cls, filepath: str = "config.json") -> 'SecurityConfig':
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                data = json.load(f)
            return cls(**data)
        return cls()
    
    @classmethod
    def load_from_env(cls) -> 'SecurityConfig':
        config = cls()
        config.base_trust_score = int(os.getenv('TRUST_BASE_SCORE', config.base_trust_score))
        config.trust_threshold_green = int(os.getenv('TRUST_THRESHOLD_GREEN', config.trust_threshold_green))
        config.trust_threshold_yellow = int(os.getenv('TRUST_THRESHOLD_YELLOW', config.trust_threshold_yellow))
        config.trust_threshold_orange = int(os.getenv('TRUST_THRESHOLD_ORANGE', config.trust_threshold_orange))
        config.rate_limit_per_minute = int(os.getenv('RATE_LIMIT_PER_MINUTE', config.rate_limit_per_minute))
        config.rate_limit_per_hour = int(os.getenv('RATE_LIMIT_PER_HOUR', config.rate_limit_per_hour))
        config.ml_similarity_threshold = float(os.getenv('ML_SIMILARITY_THRESHOLD', config.ml_similarity_threshold))
        config.ml_model_name = os.getenv('ML_MODEL_NAME', config.ml_model_name)
        return config


def get_config() -> SecurityConfig:
    """Get or create global configuration instance (thread-safe)."""
    global _config
    with _config_lock:
        if _config is None:
            if os.path.exists('config.json'):
                _config = SecurityConfig.load_from_file()
            else:
                _config = SecurityConfig.load_from_env()
                _config.save_to_file()
            # Validate
            errors = _config.validate()
            if errors:
                print("WARNING: Configuration validation errors:")
                for error in errors:
                    print(f"  - {error}")
        return _config

def reload_config() -> SecurityConfig:
    """Reload configuration from file or environment (thread-safe)."""
    global _config
    with _config_lock:
        _config = None
        return get_config()

def get_config_snapshot() -> dict:
    """Get immutable snapshot of current configuration."""
    with _config_lock:
        config = get_config()
        return config.to_dict()

