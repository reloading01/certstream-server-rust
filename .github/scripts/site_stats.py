import json
import os
import re
import urllib.request

REPO = "reloading01/certstream-server-rust"
OWNER = REPO.split("/")[0]
PACKAGE_PAGE = f"https://github.com/{REPO}/pkgs/container/certstream-server-rust"


def get(url, api=False, body=None):
    headers = {"User-Agent": "site-stats"}
    token = os.environ.get("GITHUB_TOKEN")
    if api and token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, data=body)
    with urllib.request.urlopen(request, timeout=30) as r:
        return r.read().decode()


SPONSORS_QUERY = """
query($login: String!) {
  user(login: $login) {
    sponsors(first: 100) {
      nodes {
        ... on User { login avatarUrl url }
        ... on Organization { login avatarUrl url }
      }
    }
  }
}
"""


repo = json.loads(get(f"https://api.github.com/repos/{REPO}", api=True))
page = get(PACKAGE_PAGE)

match = re.search(r'Total downloads</span>\s*<h3 title="(\d+)"', page)
if not match:
    raise SystemExit("container pull count not found on the package page")

query = json.dumps({"query": SPONSORS_QUERY, "variables": {"login": OWNER}}).encode()
sponsors = json.loads(get("https://api.github.com/graphql", api=True, body=query))
sponsors = sponsors["data"]["user"]["sponsors"]["nodes"]

stats = {
    "stars": repo["stargazers_count"],
    "container_pulls": int(match.group(1)),
    "sponsors": [{"login": s["login"], "avatar": s["avatarUrl"], "url": s["url"]} for s in sponsors],
}

with open("docs/stats.json", "w") as f:
    json.dump(stats, f, indent=2)
    f.write("\n")
print(stats)
