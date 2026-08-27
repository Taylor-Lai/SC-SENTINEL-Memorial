import re

_ALLOWED_REPOSITORY_URL = re.compile(
    r"^(https?://|git@)"
    r"(github\.com|gitlab\.com|gitee\.com|bitbucket\.org|codeup\.aliyun\.com)"
    r"[/:][\w\-.]+/[\w\-.]+?(?:\.git)?/?$",
    re.IGNORECASE,
)


def is_allowed_remote_repository_url(value: str) -> bool:
    """Return whether a URL targets an explicitly approved Git host."""
    return bool(value and _ALLOWED_REPOSITORY_URL.fullmatch(value.strip()))
