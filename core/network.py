import requests
from time import sleep
from core.config import TIMEOUT, HEADERS, MAX_RETRIES, RETRY_BACKOFF
from core.logger import warn, error

session = requests.Session()
session.headers.update(HEADERS)

def get(url, **kwargs):
    """GET request with retry logic and exponential backoff"""
    kwargs.setdefault("timeout", TIMEOUT)
    
    for attempt in range(MAX_RETRIES):
        try:
            response = session.get(url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES - 1:
                delay = TIMEOUT * (RETRY_BACKOFF ** attempt)
                warn(f"Timeout on {url}, retrying in {delay}s...")
                sleep(delay)
            else:
                error(f"Timeout on {url} after {MAX_RETRIES} attempts")
                raise
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES - 1:
                delay = TIMEOUT * (RETRY_BACKOFF ** attempt)
                warn(f"Request failed: {e}, retrying in {delay}s...")
                sleep(delay)
            else:
                error(f"Request failed: {e} after {MAX_RETRIES} attempts")
                raise
    
    return None
