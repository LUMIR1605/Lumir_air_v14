import json
import time
import requests
from core import config
from core.logger import info, error, warn
from intelligence.reasoning_engine import build_prompt

def analyze(context: str):
    """Analyze context using Ollama with retry and exponential backoff"""
    
    if not config.ENABLE_LLM:
        warn("LLM is disabled")
        return {}
    
    url = f"{config.OLLAMA_URL}/api/generate"
    model = config.OLLAMA_MODEL
    timeout = config.OLLAMA_TIMEOUT
    max_retries = config.OLLAMA_MAX_RETRIES
    
    for attempt in range(max_retries):
        try:
            info(f"Sending request to Ollama (attempt {attempt + 1}/{max_retries})")
            
            response = requests.post(
                url,
                json={
                    "model": model,
                    "prompt": build_prompt(context),
                    "stream": False,
                    "format": "json"
                },
                timeout=timeout
            )
            
            response.raise_for_status()
            data = response.json()
            
            # Parse response
            response_text = data.get("response", "")
            if not response_text:
                error("Ollama returned empty response")
                continue
            
            # Try to parse as JSON
            try:
                result = json.loads(response_text)
                info("LLM analysis completed successfully")
                return result
            except json.JSONDecodeError as e:
                error(f"Failed to parse LLM response as JSON: {e}")
                error(f"Response: {response_text[:200]}")
                continue
                
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                backoff = config.calculate_backoff(attempt)
                warn(f"Ollama timeout, retrying in {backoff}s")
                time.sleep(backoff)
            else:
                error(f"Ollama timeout after {max_retries} attempts")
                
        except requests.exceptions.ConnectionError as e:
            if attempt < max_retries - 1:
                backoff = config.calculate_backoff(attempt)
                warn(f"Ollama connection error, retrying in {backoff}s: {e}")
                time.sleep(backoff)
            else:
                error(f"Ollama connection failed after {max_retries} attempts: {e}")
                
        except requests.exceptions.RequestException as e:
            error(f"Ollama request failed: {e}")
            if attempt < max_retries - 1:
                backoff = config.calculate_backoff(attempt)
                warn(f"Retrying in {backoff}s")
                time.sleep(backoff)
            else:
                error(f"Ollama request failed after {max_retries} attempts")
    
    return {}
