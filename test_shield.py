"""Offline input detection regression; importing this module has no side effects."""
import pytest
from shield.core import detect_type

@pytest.mark.parametrize("value,expected", [
    ("test@example.com", "email"), ("example.com", "domain"),
    ("https://example.com", "url"), ("synthetic_user", "username"),
    ("+48123456789", "phone"),
])
def test_input_detection(value, expected):
    assert detect_type(value) == expected
