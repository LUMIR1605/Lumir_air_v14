import subprocess

def scan(number):
    try:
        result = subprocess.run(
            ["phoneinfoga", "scan", "-n", number],
            capture_output=True,
            text=True,
            timeout=60
        )

        output = result.stdout

        return {
            "source": "phoneinfoga",
            "status": "ok",
            "raw": output,
            "categories": output.count("Results for"),
            "google_links": output.count("https://www.google.com/search"),
            "scanner_success": "scanner(s) succeeded" in output
        }

    except Exception as e:
        return {
            "source": "phoneinfoga",
            "status": "error",
            "error": str(e)
        }
