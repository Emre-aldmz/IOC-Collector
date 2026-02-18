
from typing import Optional
from ioc_collector.sources.remote_fetcher import RemoteFetcher

class GitHubFeed:
    def __init__(self, fetcher: RemoteFetcher):
        self.fetcher = fetcher

    def fetch_from_repo(self, repo_slug: str, branch: str = "master", path: str = "trails/static/malware/malware.txt") -> Optional[str]:
        """
        Fetches a file from a GitHub repository using the raw content URL.
        
        Args:
            repo_slug (str): "owner/repo"
            branch (str): Branch name (default: master)
            path (str): Path to file within the repo.
        """
        # Handling common default paths for known repos if needed, but for now generic
        # If user provides just repo_slug, we might need a default path map, 
        # but the CLI arg design suggests strict mapping or usage. 
        # For 'stamparm/maltrail', the path is specific.
        
        # Simple heuristic for common malware list locations if path not provided?
        # For now, we'll assume the interaction/CLI handles specific paths or we default to a generic one.
        # But 'malware.txt' is specific to maltrail.
        
        raw_url = f"https://raw.githubusercontent.com/{repo_slug}/{branch}/{path}"
        return self.fetcher.fetch(raw_url)

    def fetch_raw_url(self, url: str) -> Optional[str]:
        """Fetches content from a direct raw URL."""
        return self.fetcher.fetch(url)
