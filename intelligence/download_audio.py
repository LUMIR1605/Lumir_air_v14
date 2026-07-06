from pathlib import Path
import subprocess

TMP = Path("tmp")
TMP.mkdir(exist_ok=True)

def download(url: str):

    out = TMP / "%(id)s.%(ext)s"

    cmd = [
        "yt-dlp",
        "-f", "18",
        "-x",
        "--audio-format", "mp3",
        "-o", str(out),
        url,
    ]

    subprocess.run(cmd, check=True)

    files = sorted(
        TMP.glob("*.mp3"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )

    if not files:
        raise RuntimeError("Nie pobrano pliku MP3.")

    return files[0]


if __name__ == "__main__":
    audio = download("https://youtu.be/XJktaXYRWBg")
    print(audio)
