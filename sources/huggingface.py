from core.network import get
from core.logger import info, ok, error

URL = "https://huggingface.co/api/models"

def fetch(limit=5):
    info("Pobieram Hugging Face...")

    try:
        data = get(
            URL,
            params={
                "sort": "downloads",
                "direction": "-1",
                "limit": limit
            }
        ).json()

        ok(f"Pobrano {len(data)} modeli")

        return data

    except Exception as e:
        error(str(e))
        return []
