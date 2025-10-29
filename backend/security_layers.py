import re
import time
from typing import Tuple


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


def check_prompt_anomaly(prompt: str) -> Tuple[bool, str]:
    # Naive anomaly detection: excessive length or too many special chars
    if len(prompt) > 4000:
        return False, "Prompt too long and anomalous."
    special_ratio = sum(1 for c in prompt if not c.isalnum() and not c.isspace()) / max(len(prompt), 1)
    if special_ratio > 0.2:
        return False, "Prompt contains anomalously high special character ratio."
    return True, "OK"


def check_llm_response(response: str) -> Tuple[bool, str]:
    # Basic safeguard: ensure response is not empty and doesn't contain disallowed tokens
    if not response or not response.strip():
        return False, "LLM returned an empty response."
    disallowed = ["<script>", "DROP TABLE", "BEGIN TRANSACTION"]
    if any(token.lower() in response.lower() for token in disallowed):
        return False, "LLM response contained disallowed content."
    return True, "OK"


def mock_llm_call(prompt: str, provider: str) -> str:
    # Simulated LLM response regardless of provider
    return "Secure simulated response"


def timestamp() -> float:
    return time.time()


