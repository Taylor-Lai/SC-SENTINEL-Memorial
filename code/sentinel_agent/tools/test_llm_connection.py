import json
import sys
from pathlib import Path

# Ensure project root is importable when running from tools/
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.llm_client import LLMClient


def main():
    client = LLMClient()

    print("=== LLM Config Check ===")
    print(f"base_url configured: {bool(client.base_url)}")
    print(f"model configured: {bool(client.model)}")
    print(f"api_key configured: {bool(client.api_key)}")
    print(f"endpoint: {client._chat_endpoint() if client.base_url else '<missing>'}")
    print(f"disable_proxy: {client.disable_proxy}")
    print(f"verify_ssl: {client.verify_ssl}")

    if not client.is_available():
        print("\nERROR: .env is incomplete. Please set LLM_API_KEY, LLM_BASE_URL, LLM_MODEL.")
        return

    messages = [
        {
            "role": "system",
            "content": "You are a test assistant. Return strict JSON only."
        },
        {
            "role": "user",
            "content": 'Return exactly this JSON: {"ok": true, "message": "hello"}'
        }
    ]

    print("\n=== Sending test request ===")
    try:
        text = client.chat(messages, temperature=0)
        print("Raw response:")
        print(text)
        print("\nConnection test finished.")
    except Exception as exc:
        print("ERROR:")
        print(str(exc))


if __name__ == "__main__":
    main()
