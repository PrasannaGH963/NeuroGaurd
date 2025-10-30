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
    """
    provider = provider.lower()
    try:
        if provider == "openai":
            if not OPENAI_AVAILABLE:
                logging.warning("OpenAI provider selected but openai package is not installed.")
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                logging.warning("OpenAI API key missing from environment.")
            else:
                logging.info(f"Using OpenAI with key present.")
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
        elif provider in ["claude", "anthropic"]:
            if not ANTHROPIC_AVAILABLE:
                logging.warning("Anthropic provider selected but anthropic package is not installed.")
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                logging.warning("Anthropic API key missing from environment.")
            else:
                logging.info(f"Using Anthropic with key present.")
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
        elif provider == "gemini":
            if not GOOGLE_AVAILABLE:
                logging.warning("Gemini provider selected but google-generativeai is not installed.")
            api_key = os.getenv("GOOGLE_API_KEY")
            if not api_key:
                logging.warning("Gemini API key missing from environment.")
            else:
                logging.info(f"Using Gemini with key present.")
                genai.configure(api_key=api_key)
                # Use a model that is both accessible and chat-capable for free tier
                model = genai.GenerativeModel('models/gemini-2.5-flash')
                response = await asyncio.wait_for(
                    model.generate_content_async(prompt),
                    timeout=timeout
                )
                logging.info("Gemini response received.")
                return str(response.text)
    except asyncio.TimeoutError:
        logging.error(f"LLM request timed out after {timeout}s")
        raise
    except Exception as e:
        logging.error(f"LLM generation error ({provider}): {e}")
        raise
    # Fallback to mock
    logging.info(f"Using mock response (provider={provider}, API key(s) or package likely missing)")
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
