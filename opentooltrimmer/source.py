from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse


USER_AGENT = "OpenToolTrimmer/0.1"
SNAPSHOT_IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache"}


def _snapshot_files(root: Path):
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if any(part in SNAPSHOT_IGNORED_DIRS for part in path.relative_to(root).parts):
            continue
        yield path


def repository_byte_count(root: Path) -> int:
    return sum(path.stat().st_size for path in _snapshot_files(root))


def _tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for path in _snapshot_files(root):
        rel = path.relative_to(root).as_posix().encode("utf-8")
        h.update(rel)
        h.update(b"\0")
        try:
            h.update(path.read_bytes())
        except OSError:
            continue
        h.update(b"\0")
    return h.hexdigest()


def _git_revision(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3,
        )
        rev = result.stdout.strip()
        return rev or None
    except Exception:
        return None


def _github_parts(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        raise ValueError("V0.1 remote sources must be public github.com repository URLs")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise ValueError("GitHub URL must include owner/repository")
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def _api_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.load(response)


def _download(url: str, target: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as response, target.open("wb") as out:
        shutil.copyfileobj(response, out)


@contextmanager
def resolved_source(source: str):
    local = Path(source).expanduser()
    if local.exists():
        root = local.resolve()
        if not root.is_dir():
            raise ValueError("repository source must be a directory")
        yield {
            "root": root,
            "source": str(root),
            "revision": _git_revision(root),
            "snapshot_sha256": _tree_digest(root),
        }
        return

    owner, repo = _github_parts(source)
    with tempfile.TemporaryDirectory(prefix="opentooltrimmer-") as temp:
        tempdir = Path(temp)
        revision = None
        default_branch = "main"
        try:
            metadata = _api_json(f"https://api.github.com/repos/{owner}/{repo}")
            default_branch = metadata.get("default_branch") or "main"
            branch = _api_json(f"https://api.github.com/repos/{owner}/{repo}/branches/{default_branch}")
            revision = ((branch.get("commit") or {}).get("sha"))
        except (OSError, urllib.error.URLError, ValueError, KeyError):
            pass

        archive = tempdir / "repo.zip"
        attempts = [default_branch]
        if default_branch != "main":
            attempts.append("main")
        if "master" not in attempts:
            attempts.append("master")

        last_error = None
        for branch_name in attempts:
            try:
                _download(f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch_name}", archive)
                default_branch = branch_name
                break
            except Exception as exc:
                last_error = exc
        else:
            raise RuntimeError(f"could not download GitHub repository: {last_error}")

        with zipfile.ZipFile(archive) as zf:
            zf.extractall(tempdir / "expanded")
        roots = [p for p in (tempdir / "expanded").iterdir() if p.is_dir()]
        if len(roots) != 1:
            raise RuntimeError("unexpected GitHub archive layout")
        root = roots[0]

        yield {
            "root": root,
            "source": f"https://github.com/{owner}/{repo}",
            "revision": revision or f"branch:{default_branch}",
            "snapshot_sha256": _tree_digest(root),
        }
