from core.network import get
from core.logger import info, ok, error
import xml.etree.ElementTree as ET

RSS = {
    "OpenAI": "https://openai.com/news/rss.xml",
    "Google AI": "https://blog.google/technology/ai/rss/",
}

def fetch():
    """Fetch AI news from RSS feeds"""
    info("Pobieram AI News...")
    
    result = []
    
    for source, url in RSS.items():
        try:
            response = get(url)
            xml = response.text
            root = ET.fromstring(xml)
            
            count = 0
            
            for item in root.findall(".//item"):
                result.append({
                    "source": source,
                    "title": item.findtext("title", ""),
                    "link": item.findtext("link", "")
                })
                
                count += 1
                
                if count >= 3:
                    break
        
        except Exception as e:
            error(f"Failed to fetch {source} RSS: {e}")
            continue
    
    ok(f"Pobrano {len(result)} wiadomości")
    
    return result
