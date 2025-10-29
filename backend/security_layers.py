import re
import time
import math
from typing import Tuple, Optional
from collections import Counter
from config import get_config


def check_prompt_injection(prompt: str) -> Tuple[bool, str]:
    lowered = prompt.lower()
    injection_patterns = [
        # Direct instruction override attempts
        r"ignore (all|any|previous|prior) instructions?",
        r"disregard previous",
        r"forget (you are|that you are|everything)",
        r"pretend (you are|that you are)",
        r"act as (if|though)",
        r"roleplay as",
        
        # System prompt extraction attempts
        r"reveal (your )?(system|hidden|secret|internal) prompt",
        r"(show|tell|give|provide|return) (me |us )?(the |your )?(system|hidden|secret|internal|original) prompt",
        r"what (are |were |is )?(your )?(initial|system) instructions?",
        
        # Safety bypass attempts
        r"override (safety|security|protections?)",
        r"ignore (safety|security) (rules?|protections?|guidelines?)",
        r"bypass (safety|security|protections?)",
        r"disable (safety|security|protections?)",
        r"forget (safety|security) (rules?|protections?|guidelines?)",
        r"ignore any (safety|security) rules?",
        
        # Model/identity manipulation
        r"(you are|you're) (now|a|an) (system admin|administrator|different model|another model)",
        r"(you are|you're) (a|an) (different|another) model",
        r"(you are|you're) no longer",
        r"you must ignore",
        
        # Training data extraction
        r"(return|give|provide|show|tell|reveal) (me |us )?(the |your )?(original|training|source) data",
        r"(return|give|provide|show|tell|reveal) (me |us )?(the |your )?training (data|set|examples?)",
    ]
    for pattern in injection_patterns:
        if re.search(pattern, lowered, re.IGNORECASE):
            return False, "Potential prompt injection detected."
    return True, "OK"


def check_content_safety(prompt: str) -> Tuple[bool, str]:
    lowered = prompt.lower()
    
    # Violence and harmful content
    violence_keywords = [
        "violence", "bomb", "terror", "hate", "dox", "self-harm",
        "kill", "murder", "assault", "weapon",
    ]
    if any(word in lowered for word in violence_keywords):
        return False, "Content safety policy triggered."
    
    # Credential and sensitive data requests
    credential_patterns = [
        r"\bapi keys?\b",
        r"(give|provide|show|tell|reveal|share|send) (me |us )?(some |any |your |the )?(api|access) (key|keys|token|tokens|credentials?)",
        r"(give|provide|show|tell|reveal|share|send) (me |us )?(your |the )?(password|passwords?|secret|secrets?|credential|credentials?)",
        r"(give|provide|show|tell|reveal|share|send) (me |us )?(your |the )?(authentication|auth) (token|tokens?|key|keys?)",
    ]
    for pattern in credential_patterns:
        if re.search(pattern, lowered, re.IGNORECASE):
            return False, "Content safety policy triggered: Credential request detected."
    
    return True, "OK"


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of text.
    Higher entropy = more random, lower = more repetitive.
    """
    if not text:
        return 0.0
    
    counter = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) 
                   for count in counter.values() if count > 0)
    return entropy


def detect_repetition(text: str, min_length: int = 3, max_repetitions: int = 3) -> Optional[str]:
    """
    Detect repeated sequences in text.
    
    Args:
        text: Input text to analyze
        min_length: Minimum length of sequence to check
        max_repetitions: Maximum allowed repetitions
        
    Returns:
        Repeated sequence if found, None otherwise
    """
    for length in range(min_length, len(text) // (max_repetitions + 1) + 1):
        for i in range(len(text) - length * (max_repetitions + 1) + 1):
            sequence = text[i:i + length]
            count = text.count(sequence)
            if count > max_repetitions:
                return sequence
    return None


def check_prompt_anomaly(prompt: str) -> Tuple[bool, str]:
    """
    Enhanced anomaly detection with multiple checks.
    """
    config = get_config()
    
    # Length check
    if len(prompt) > config.max_prompt_length:
        return False, f"Prompt exceeds maximum length ({config.max_prompt_length})"
    
    if not prompt.strip():
        return False, "Empty prompt detected"
    
    # Special character ratio
    special_ratio = sum(1 for c in prompt if not c.isalnum() and not c.isspace()) / max(len(prompt), 1)
    if special_ratio > config.max_special_char_ratio:
        return False, f"Excessive special characters detected ({special_ratio:.2%})"
    
    # Unicode/non-ASCII detection
    non_ascii_count = sum(1 for c in prompt if ord(c) > 127)
    non_ascii_ratio = non_ascii_count / max(len(prompt), 1)
    if non_ascii_ratio > config.max_non_ascii_ratio:
        return False, f"Suspicious encoding detected ({non_ascii_ratio:.2%} non-ASCII)"
    
    # Repetition detection
    repeated = detect_repetition(prompt, max_repetitions=config.max_repetition_count)
    if repeated:
        return False, f"Repetitive pattern detected: '{repeated[:20]}...'"
    
    # Entropy analysis
    entropy = calculate_entropy(prompt)
    if entropy < config.min_entropy:
        return False, f"Prompt entropy too low ({entropy:.2f} - repetitive pattern)"
    if entropy > config.max_entropy:
        return False, f"Prompt entropy too high ({entropy:.2f} - random data)"
    
    # Token-to-character ratio (simple estimation)
    tokens = prompt.split()
    char_count = len(prompt)
    if char_count > 0:
        token_ratio = len(tokens) / char_count
        if token_ratio > config.max_token_to_char_ratio:
            return False, f"Token stuffing detected (ratio: {token_ratio:.2f})"
    
    return True, "OK"


def check_context_integrity(prompt: str) -> Tuple[bool, str]:
    """
    Check context integrity - ensures prompt maintains conversational context.
    This is a placeholder for future implementation.
    For now, checks basic context coherence.
    """
    # Basic check: prompt should have reasonable word count
    words = prompt.split()
    if len(words) < 1:
        return False, "Empty context"
    
    # Check for context poisoning attempts
    context_poison_patterns = [
        r"this is a test",
        r"ignore the above",
        r"forget everything",
    ]
    
    lowered = prompt.lower()
    for pattern in context_poison_patterns:
        if re.search(pattern, lowered):
            return False, "Context integrity violation detected"
    
    return True, "OK"


def check_llm_response(response: str, original_prompt: str = "") -> Tuple[bool, str]:
    """
    Enhanced response validation with PII detection, code injection, and URL safety.
    
    Args:
        response: LLM response text to validate
        original_prompt: Original user prompt for echo attack detection
    """
    config = get_config()
    
    # Basic validation
    if not response or not response.strip():
        return False, "Empty response received"
    
    # Length validation (warning threshold, not blocking)
    if len(response) > config.max_response_length:
        # This is logged but doesn't block
        pass
    
    # PII Detection patterns
    pii_patterns = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone_us': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
    }
    
    for pii_type, pattern in pii_patterns.items():
        if re.search(pattern, response):
            return False, f"PII detected in response: {pii_type}"
    
    # Code injection detection
    code_patterns = [
        (r'<script[^>]*>.*?</script>', 'JavaScript injection'),
        (r'<iframe[^>]*>', 'iframe injection'),
        (r'DROP\s+TABLE', 'SQL injection (DROP TABLE)'),
        (r'DELETE\s+FROM', 'SQL injection (DELETE)'),
        (r'SELECT\s+\*\s+FROM', 'SQL injection (SELECT)'),
        (r';\s*rm\s+-rf', 'Shell command injection'),
        (r'eval\s*\(', 'JavaScript eval'),
        (r'exec\s*\(', 'Python exec'),
        (r'__import__\s*\(', 'Python import'),
        (r'document\.cookie', 'Cookie access attempt'),
        (r'window\.location', 'Location manipulation')
    ]
    
    for pattern, description in code_patterns:
        if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
            return False, f"Potential code injection in response: {description}"
    
    # URL safety check
    url_pattern = r'https?://[^\s<>"\'\)]+'
    urls = re.findall(url_pattern, response, re.IGNORECASE)
    dangerous_extensions = ['.exe', '.scr', '.bat', '.cmd', '.zip', '.rar', '.7z', '.dmg', '.pkg']
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']  # Free hosting services often used for malware
    
    for url in urls:
        url_lower = url.lower()
        # Check for dangerous file extensions
        if any(url_lower.endswith(ext) for ext in dangerous_extensions):
            return False, f"Suspicious URL detected in response (dangerous extension): {url[:50]}"
        
        # Check for suspicious TLDs in URLs that appear malicious
        for tld in suspicious_tlds:
            if tld in url_lower and len(url.split('/')) > 4:  # Multiple path segments
                # Additional check: if URL looks suspicious
                return False, f"Suspicious URL detected: {url[:50]}"
    
    # Echo attack detection
    if original_prompt:
        prompt_stripped = original_prompt.strip().lower()
        response_stripped = response.strip().lower()
        if prompt_stripped and prompt_stripped == response_stripped:
            return False, "Response mirrors prompt exactly (echo attack)"
        
        # Check for exact repetition of prompt within response
        if len(prompt_stripped) > 20 and prompt_stripped in response_stripped:
            # If prompt is significantly long and appears verbatim in response
            return False, "Prompt verbatim repetition detected in response"
    
    # JSON structure validation (if response claims to be JSON)
    json_indicators = ['{', '}', '[', ']']
    if any(indicator in response for indicator in json_indicators):
        # Try to parse as JSON to validate structure
        try:
            import json
            # Check if response starts/ends with JSON-like structure
            stripped = response.strip()
            if (stripped.startswith('{') and stripped.endswith('}')) or \
               (stripped.startswith('[') and stripped.endswith(']')):
                json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            # Not valid JSON, but that's OK - just not blocking
            pass
    
    # Basic disallowed content check (legacy)
    critical_disallowed = ["<script>", "DROP TABLE", "BEGIN TRANSACTION", "rm -rf /"]
    if any(token.lower() in response.lower() for token in critical_disallowed):
        return False, "LLM response contained disallowed content"
    
    return True, "OK"


def mock_llm_call(prompt: str, provider: str) -> str:
    # Simulated LLM response regardless of provider
    return "Secure simulated response"


def timestamp() -> float:
    return time.time()


