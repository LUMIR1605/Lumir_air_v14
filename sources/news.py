from core.network import get
from core.logger import info, ok
import xml.etree.ElementTree as ET

RSS = {
    "OpenAI": "https://openai.com/news/rss.xml",
    "Google AI": "https://blog.google/technology/ai/rss/",
}

def fetch():

    info("Pobieram AI News...")

    result = []

    for source, url in RSS.items():

        try:
            xml = get(url).text
            root = ET.fromstring(xml)

            count = 0

            for item in root.findall(".//item"):

                result.append({
                    "source": source,
                    "title": item.findtext("title",""),
                    "link": item.findtext("link","")
                })

                count += 1

                if count >= 3:
                    break

        except Exception:
            continue

    ok(f"Pobrano {len(result)} wiadomości")

    return result
