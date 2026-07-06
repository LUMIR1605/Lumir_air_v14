from intelligence.music_collector import add
import sys

if len(sys.argv)<3:
    print('Użycie:')
    print('python add_song.py "Tytuł" "Artysta"')
    raise SystemExit

add(
    source="research",
    title=sys.argv[1],
    artist=sys.argv[2]
)

print("✅ Dodano do kolejki.")
