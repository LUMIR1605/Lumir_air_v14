from intelligence.music_sources import enabled_sources

def fetch():
    print("🎵 Music Collector")

    for source in enabled_sources():
        print(f"→ {source}")

        # TODO:
        # tutaj będzie pobieranie z Beatport / YouTube / Spotify

    return True

if __name__ == "__main__":
    fetch()
