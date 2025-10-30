"""
Real LLM provider integration (OpenAI, Anthropic, Gemini).
Falls back to mock if not configured.
"""
import os
import logging
from typing import Optional
import asyncio

# Optional imports
try:
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    AsyncOpenAI = None
    OPENAI_AVAILABLE = False

try:
    from anthropic import AsyncAnthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    AsyncAnthropic = None
    ANTHROPIC_AVAILABLE = False

try:
    import google.generativeai as genai
    GOOGLE_AVAILABLE = True
except ImportError:
    genai = None
    GOOGLE_AVAILABLE = False

async def generate_llm_response(prompt: str, provider: str, timeout: int = 30) -> str:
    """
    Generate LLM response. Falls back to mock if not configured.
    Args:
        prompt: User input
        provider: 'openai', 'claude', or 'gemini'
        timeout: seconds
    Returns:
        LLM response string
    """
    provider = provider.lower()
    try:
        if provider == "openai" and OPENAI_AVAILABLE:
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                client = AsyncOpenAI(api_key=api_key)
                response = await asyncio.wait_for(
                    client.chat.completions.create(
                        model="gpt-4",
                        messages=[{"role": "user", "content": prompt}],
                        max_tokens=1000
                    ),
                    timeout=timeout
                )
                return response.choices[0].message.content
        elif provider in ["claude", "anthropic"] and ANTHROPIC_AVAILABLE:
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if api_key:
                client = AsyncAnthropic(api_key=api_key)
                response = await asyncio.wait_for(
                    client.messages.create(
                        model="claude-3-5-sonnet-20241022",
                        max_tokens=1000,
                        messages=[{"role": "user", "content": prompt}]
                    ),
                    timeout=timeout
                )
                return response.content[0].text
        elif provider == "gemini" and GOOGLE_AVAILABLE:
            api_key = os.getenv("GOOGLE_API_KEY")
            if api_key:
                genai.configure(api_key=api_key)
                model = genai.GenerativeModel('gemini-pro')
                response = await asyncio.wait_for(
                    model.generate_content_async(prompt),
                    timeout=timeout
                )
                return str(response.text)
    except asyncio.TimeoutError:
        logging.error(f"LLM request timed out after {timeout}s")
        raise
    except Exception as e:
        logging.error(f"LLM generation error: {e}")
        raise
    # Fallback to mock
    logging.info(f"Using mock response (API key not configured for {provider})")
    return f"[Mock response] This is a simulated secure response to: {prompt[:50]}..."

def is_llm_configured(provider: str) -> bool:
    """Check if LLM provider is configured with an API key."""
    provider = provider.lower()
    if provider == "openai":
        return OPENAI_AVAILABLE and bool(os.getenv("OPENAI_API_KEY"))
    elif provider in ["claude", "anthropic"]:
        return ANTHROPIC_AVAILABLE and bool(os.getenv("ANTHROPIC_API_KEY"))
    elif provider == "gemini":
        return GOOGLE_AVAILABLE and bool(os.getenv("GOOGLE_API_KEY"))
    return False
