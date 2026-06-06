"""GitHub API tools for fetching PR data and posting reviews."""

from typing import Any, Dict, List, Optional

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)

GITHUB_API_BASE = "https://api.github.com"


def _get_github_headers(token: Optional[str] = None) -> Dict[str, str]:
    """Build GitHub API headers with authentication."""
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif settings.GITHUB_APP_PRIVATE_KEY:
        headers["Authorization"] = f"Bearer {settings.GITHUB_APP_PRIVATE_KEY}"
    return headers


async def fetch_pr_diff(
    repo: str,
    pr_number: int,
    token: Optional[str] = None,
) -> str:
    """
    Fetch the raw unified diff for a pull request.

    Args:
        repo: Repository in "owner/repo" format
        pr_number: Pull request number
        token: GitHub API token

    Returns:
        Raw diff string
    """
    url = f"{GITHUB_API_BASE}/repos/{repo}/pulls/{pr_number}"
    headers = _get_github_headers(token)
    headers["Accept"] = "application/vnd.github.v3.diff"

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)
        if response.status_code == 200:
            return response.text
        elif response.status_code == 404:
            raise ValueError(f"PR {repo}#{pr_number} not found")
        elif response.status_code == 403:
            raise PermissionError(f"GitHub API rate limit or auth error: {response.status_code}")
        else:
            logger.error(
                "github.fetch_diff_failed",
                repo=repo,
                pr=pr_number,
                status=response.status_code,
            )
            raise RuntimeError(f"GitHub API error: {response.status_code}")


async def get_pr_files(
    repo: str,
    pr_number: int,
    token: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Get the list of files changed in a pull request.

    Returns list of file objects with filename, status, additions, deletions, patch.
    """
    url = f"{GITHUB_API_BASE}/repos/{repo}/pulls/{pr_number}/files"
    headers = _get_github_headers(token)
    all_files = []
    page = 1

    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            response = await client.get(
                url,
                headers=headers,
                params={"per_page": 100, "page": page},
            )
            if response.status_code != 200:
                logger.error(
                    "github.get_files_failed",
                    repo=repo,
                    pr=pr_number,
                    status=response.status_code,
                )
                break

            files = response.json()
            if not files:
                break

            all_files.extend([
                {
                    "filename": f["filename"],
                    "status": f["status"],
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                    "changes": f.get("changes", 0),
                    "patch": f.get("patch", ""),
                    "blob_url": f.get("blob_url", ""),
                    "raw_url": f.get("raw_url", ""),
                }
                for f in files
            ])

            if len(files) < 100:
                break
            page += 1

    logger.info("github.got_files", repo=repo, pr=pr_number, file_count=len(all_files))
    return all_files


async def get_file_content(
    repo: str,
    file_path: str,
    ref: str,
    token: Optional[str] = None,
) -> Optional[str]:
    """Fetch raw file content from a specific commit/branch ref."""
    url = f"{GITHUB_API_BASE}/repos/{repo}/contents/{file_path}"
    headers = _get_github_headers(token)

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(url, headers=headers, params={"ref": ref})
        if response.status_code == 200:
            import base64
            data = response.json()
            if data.get("encoding") == "base64":
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return None


async def post_pr_comment(
    repo: str,
    pr_number: int,
    body: str,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Post a general comment on a pull request."""
    url = f"{GITHUB_API_BASE}/repos/{repo}/issues/{pr_number}/comments"
    headers = _get_github_headers(token)

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(url, headers=headers, json={"body": body})
        if response.status_code == 201:
            result = response.json()
            logger.info("github.comment_posted", repo=repo, pr=pr_number, comment_id=result["id"])
            return result
        else:
            logger.error(
                "github.comment_failed",
                repo=repo,
                pr=pr_number,
                status=response.status_code,
                body=response.text[:200],
            )
            raise RuntimeError(f"Failed to post comment: {response.status_code}")


async def create_review(
    repo: str,
    pr_number: int,
    commit_id: str,
    body: str,
    comments: List[Dict[str, Any]],
    event: str = "COMMENT",
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a pull request review with inline comments.

    Args:
        repo: Repository in "owner/repo" format
        pr_number: PR number
        commit_id: HEAD commit SHA
        body: Review summary body
        comments: List of inline comments [{path, line, body}]
        event: "APPROVE", "REQUEST_CHANGES", or "COMMENT"
        token: GitHub token
    """
    url = f"{GITHUB_API_BASE}/repos/{repo}/pulls/{pr_number}/reviews"
    headers = _get_github_headers(token)

    payload = {
        "commit_id": commit_id,
        "body": body,
        "event": event,
        "comments": [
            {
                "path": c["path"],
                "line": c.get("line", 1),
                "body": c["body"],
                "side": c.get("side", "RIGHT"),
            }
            for c in comments[:50]  # GitHub limits to 50 inline comments per review
        ],
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)
        if response.status_code in (200, 201):
            result = response.json()
            logger.info(
                "github.review_created",
                repo=repo,
                pr=pr_number,
                review_id=result.get("id"),
                comments_count=len(comments),
            )
            return result
        else:
            logger.error(
                "github.review_failed",
                repo=repo,
                pr=pr_number,
                status=response.status_code,
                body=response.text[:500],
            )
            raise RuntimeError(f"Failed to create review: {response.status_code}")


async def get_pr_metadata(
    repo: str,
    pr_number: int,
    token: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch full PR metadata from GitHub API."""
    url = f"{GITHUB_API_BASE}/repos/{repo}/pulls/{pr_number}"
    headers = _get_github_headers(token)

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {
                "number": data["number"],
                "title": data["title"],
                "body": data.get("body", ""),
                "state": data["state"],
                "author": data["user"]["login"],
                "base_branch": data["base"]["ref"],
                "head_branch": data["head"]["ref"],
                "head_sha": data["head"]["sha"],
                "diff_url": data["diff_url"],
                "html_url": data["html_url"],
                "files_changed": data.get("changed_files", 0),
                "additions": data.get("additions", 0),
                "deletions": data.get("deletions", 0),
                "created_at": data["created_at"],
                "updated_at": data["updated_at"],
            }
        raise RuntimeError(f"Failed to fetch PR: {response.status_code}")
