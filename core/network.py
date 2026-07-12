import requests
from time import sleep
from core.config import TIMEOUT, HEADERS, MAX_RETRIES, RETRY_BACKOFF, RETRY_DELAY
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
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else None
            if status_code is not None and 400 <= status_code < 500:
                error(f"Request failed: {e}")
                raise
            if attempt < MAX_RETRIES - 1:
                delay = RETRY_DELAY * (RETRY_BACKOFF ** attempt)
                warn(f"Request failed: {e}, retrying in {delay}s...")
                sleep(delay)
            else:
                error(f"Request failed: {e} after {MAX_RETRIES} attempts")
                raise
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES - 1:
                delay = RETRY_DELAY * (RETRY_BACKOFF ** attempt)
                warn(f"Timeout on {url}, retrying in {delay}s...")
                sleep(delay)
            else:
                error(f"Timeout on {url} after {MAX_RETRIES} attempts")
                raise
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES - 1:
                delay = RETRY_DELAY * (RETRY_BACKOFF ** attempt)
                warn(f"Request failed: {e}, retrying in {delay}s...")
                sleep(delay)
            else:
                error(f"Request failed: {e} after {MAX_RETRIES} attempts")
                raise
    
    return None
