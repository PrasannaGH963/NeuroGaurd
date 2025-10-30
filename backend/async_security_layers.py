"""
Async versions of security layer checks for parallel processing.
"""
import asyncio
from typing import Tuple, Dict
from security_layers import (
    check_prompt_injection,
    check_content_safety,
    check_prompt_anomaly,
    check_context_integrity,
    check_llm_response,
)
from ml_detection import IntentClassifier, check_ml_intent

async def check_prompt_injection_async(prompt: str) -> Tuple[bool, str]:
    return await asyncio.to_thread(check_prompt_injection, prompt)

async def check_content_safety_async(prompt: str) -> Tuple[bool, str]:
    return await asyncio.to_thread(check_content_safety, prompt)

async def check_prompt_anomaly_async(prompt: str) -> Tuple[bool, str]:
    return await asyncio.to_thread(check_prompt_anomaly, prompt)

async def check_context_integrity_async(prompt: str) -> Tuple[bool, str]:
    return await asyncio.to_thread(check_context_integrity, prompt)

async def check_ml_intent_async(prompt: str, classifier: IntentClassifier) -> Tuple[bool, str, dict]:
    return await asyncio.to_thread(check_ml_intent, prompt, classifier)

async def check_llm_response_async(response: str, original_prompt: str = "") -> Tuple[bool, str]:
    return await asyncio.to_thread(check_llm_response, response, original_prompt)

async def run_all_security_checks(
    prompt: str,
    classifier: IntentClassifier
) -> Dict[str, Tuple]:
    """
    Run all security checks concurrently.
    Returns dict from layer name to result tuple.
    """
    results = await asyncio.gather(
        check_prompt_injection_async(prompt),
        check_content_safety_async(prompt),
        check_prompt_anomaly_async(prompt),
        check_context_integrity_async(prompt),
        check_ml_intent_async(prompt, classifier),
        return_exceptions=True
    )
    layer_results = {}
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            layer_results[f'layer_{i}'] = (False, f"Exception: {repr(result)}")
        else:
            if i == 0:
                layer_results['prompt_injection'] = result
            elif i == 1:
                layer_results['content_safety'] = result
            elif i == 2:
                layer_results['anomaly_detection'] = result
            elif i == 3:
                layer_results['context_integrity'] = result
            elif i == 4:
                layer_results['ml_intent'] = result
    return layer_results
