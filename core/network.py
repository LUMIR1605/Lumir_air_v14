import requests

from core.config import TIMEOUT, HEADERS

session = requests.Session()
session.headers.update(HEADERS)

def get(url, **kwargs):
    kwargs.setdefault("timeout", TIMEOUT)
    response = session.get(url, **kwargs)
    response.raise_for_status()
    return response
