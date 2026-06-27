from core.config import APP_NAME, VERSION
from sources.github import fetch

print("=" * 60)
print(f"{APP_NAME} v{VERSION}")
print("=" * 60)

repos = fetch()

print()

for i, repo in enumerate(repos, 1):
    print(f"\n{i}. {repo['full_name']}")
    print(f"⭐ {repo['stargazers_count']:,}")
    print(f"🍴 {repo['forks_count']:,}")
    print(f"📝 {repo.get('description') or 'Brak opisu'}")
    print(f"🔗 {repo['html_url']}")
