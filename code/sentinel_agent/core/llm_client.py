import json
import os
import re
import ssl
import urllib.request
import urllib.error

from core.env_loader import load_dotenv


class LLMClient:
    """
    OpenAI-compatible chat completion client.

    Part 3.1:
    - Prefer requests if installed because it is usually more stable on Windows/Conda.
    - Fall back to urllib from the standard library.
    - Support optional proxy disabling:
        LLM_DISABLE_PROXY=1
    - Support optional SSL verification disabling for local/self-signed gateways:
        LLM_VERIFY_SSL=0
      Use this only for debugging or trusted internal gateways.
    """

    def __init__(self):
        load_dotenv(".env")

        self.api_key = os.getenv("LLM_API_KEY", "").strip()
        self.base_url = os.getenv("LLM_BASE_URL", "").strip().rstrip("/")
        self.model = os.getenv("LLM_MODEL", "").strip()
        self.timeout = int(os.getenv("LLM_TIMEOUT", "60"))
        self.temperature = float(os.getenv("LLM_TEMPERATURE", "0"))

        self.disable_proxy = os.getenv("LLM_DISABLE_PROXY", "0").strip() == "1"
        self.verify_ssl = os.getenv("LLM_VERIFY_SSL", "1").strip() != "0"

    def is_available(self):
        return bool(self.api_key and self.base_url and self.model)

    def chat(self, messages, temperature=None):
        if not self.is_available():
            raise RuntimeError(
                "LLM is not configured. Please set LLM_API_KEY, LLM_BASE_URL, and LLM_MODEL in .env."
            )

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature
        }

        # Prefer requests if available.
        try:
            import requests
            return self._chat_with_requests(payload, requests)
        except ImportError:
            return self._chat_with_urllib(payload)

    def _chat_endpoint(self):
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return self.base_url.rstrip("/") + "/chat/completions"

    def _chat_with_requests(self, payload, requests):
        endpoint = self._chat_endpoint()

        session = requests.Session()
        if self.disable_proxy:
            session.trust_env = False

        resp = session.post(
            endpoint,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            },
            json=payload,
            timeout=self.timeout,
            verify=self.verify_ssl
        )

        if resp.status_code >= 400:
            raise RuntimeError(f"LLM HTTP error {resp.status_code}: {resp.text[:1000]}")

        try:
            data = resp.json()
        except Exception as exc:
            raise RuntimeError(f"LLM response is not JSON: {resp.text[:1000]}") from exc

        try:
            return data["choices"][0]["message"]["content"]
        except Exception as exc:
            raise RuntimeError(f"Unexpected LLM response format: {data}") from exc

    def _chat_with_urllib(self, payload):
        endpoint = self._chat_endpoint()
        body = json.dumps(payload).encode("utf-8")

        handlers = []
        if self.disable_proxy:
            handlers.append(urllib.request.ProxyHandler({}))

        if not self.verify_ssl:
            ssl_context = ssl._create_unverified_context()
            handlers.append(urllib.request.HTTPSHandler(context=ssl_context))

        opener = urllib.request.build_opener(*handlers)

        req = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            },
            method="POST"
        )

        try:
            with opener.open(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"LLM HTTP error {exc.code}: {error_body}") from exc
        except Exception as exc:
            raise RuntimeError(f"LLM request failed: {exc}") from exc

        try:
            return data["choices"][0]["message"]["content"]
        except Exception as exc:
            raise RuntimeError(f"Unexpected LLM response format: {data}") from exc


def extract_json_object(text):
    """
    Robustly extract a JSON object from LLM output.

    Handles:
    - pure JSON
    - ```json fenced code block
    - prose + JSON object
    """
    if text is None:
        raise ValueError("Empty LLM output")

    text = text.strip()

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"No JSON object found in LLM output: {text[:300]}")

    candidate = text[start:end + 1]
    return json.loads(candidate)
