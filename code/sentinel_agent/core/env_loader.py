from pathlib import Path
import os


def load_dotenv(dotenv_path=".env"):
    """
    Minimal .env loader using only Python standard library.

    Supported format:
        KEY=value
        KEY="value"
        KEY='value'

    Existing environment variables will not be overwritten.
    """
    path = Path(dotenv_path)
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if not key:
            continue

        if (
            len(value) >= 2
            and ((value[0] == value[-1] == '"') or (value[0] == value[-1] == "'"))
        ):
            value = value[1:-1]

        os.environ.setdefault(key, value)
