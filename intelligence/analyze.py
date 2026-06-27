def analyze(github, hackernews, huggingface):

    repo = github[0]["full_name"] if github else "Brak"
    stars = github[0].get("stargazers_count", github[0].get("stars", "?")) if github else "?"

    hn = hackernews[0]["title"] if hackernews else "Brak"

    model = huggingface[0]["id"] if huggingface else "Brak"

    return {

        "opportunity":
f"""Największy trend dnia to:

• GitHub: {repo}
• Hacker News: {hn}
• Model AI: {model}

Jeżeli trend utrzyma się przez kilka dni, warto przygotować materiał i wykorzystać go jako przewagę.""",

        "video":
f"""Tytuł:
5 narzędzi AI, które właśnie zmieniają Internet

Plan:
1. GitHub → {repo}
2. Hacker News → {hn}
3. Model → {model}
4. Dlaczego warto śledzić ten trend.
5. Co będzie następne?""",

        "suno":
f"""TITLE:
Future Beyond AI

STYLE:
Cinematic Melodic Techno

MOOD:
Epic • Hope • Discovery

BPM:
126

VOCALS:
Female emotional voice

INSTRUMENTS:
Analog synths
Deep bass
Wide pads
Cinematic strings

IDEA:
Inspired by {repo} and {model}.

NEGATIVE:
No rap.
No distortion.
No low quality."""
    }
