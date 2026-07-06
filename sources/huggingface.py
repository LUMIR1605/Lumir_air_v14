from core.network import get
from core.logger import info, ok, error

URL = "https://huggingface.co/api/models"

def fetch(limit=5):
    """Fetch top models from Hugging Face"""
    info("Pobieram Hugging Face...")
    
    try:
        response = get(
            URL,
            params={
                "sort": "downloads",
                "direction": "-1",
                "limit": limit
            }
        )
        
        data = response.json()
        
        ok(f"Pobrano {len(data)} modeli")
        
        return data
    
    except Exception as e:
        error(str(e))
        return []
