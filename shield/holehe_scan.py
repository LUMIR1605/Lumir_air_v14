import subprocess

def scan(email):
    try:
        result = subprocess.run(
            ["holehe", "--only-used", "--no-color", email],
            capture_output=True,
            text=True,
            timeout=120
        )

        services = []

        for line in result.stdout.splitlines():
            if line.startswith("[+]"):
                name = line[3:].strip()
                if "Email used" in name:
                    continue
                services.append(name)

        return {
            "module": "holehe",
            "checked": len(result.stdout.splitlines()),
            "found": len(services),
            "services": services,
            "risk": "high" if len(services) > 20 else "medium" if len(services) > 5 else "low"
        }

    except Exception as e:
        return {
            "module": "holehe",
            "error": str(e)
        }
