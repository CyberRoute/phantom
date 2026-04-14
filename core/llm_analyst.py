"""
LLM integration — streams packet analysis via Ollama or the Anthropic API.
"""

import json
import os

import requests
from PySide6.QtCore import QThread, Signal  # pylint: disable=E0611

ANTHROPIC_MODELS = [
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-haiku-4-5",
]

OLLAMA_BASE = "http://localhost:11434"
OLLAMA_URL = f"{OLLAMA_BASE}/api/generate"


def fetch_ollama_models() -> list[str]:
    """Return the list of model names available on the local Ollama server."""
    try:
        resp = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=3)
        resp.raise_for_status()
        return [m["name"] for m in resp.json().get("models", [])]
    except Exception:  # pylint: disable=broad-exception-caught
        return []

SYSTEM_PROMPT = """You are an IoT security researcher specialising in vulnerability discovery
on embedded and smart devices.
You will be given a decoded network packet captured during a MITM session against an IoT or specialised device.
Analyse it and report concisely:
- Device type / firmware fingerprint clues (banner, UA, protocol quirks)
- Protocol and service in use — flag any plaintext, unencrypted, or legacy protocols (HTTP, Telnet, MQTT without TLS, CoAP, mDNS, UPnP, etc.)
- Credentials, API keys, tokens, or sensitive data visible in the clear
- Known CVE patterns or exploit primitives (default creds, unauthenticated endpoints, buffer-overflow indicators, command injection vectors)
- Insecure update mechanisms or unverified firmware fetches
- Unusual beaconing, C2 indicators, or data exfiltration patterns
- One-line risk rating: Low / Medium / High / Critical — with a short justification
Be specific and technical. No preamble. If nothing suspicious is found, say so briefly."""


class OllamaThread(QThread):
    """Streams an LLM analysis of a packet. Emits token by token."""

    token = Signal(str)  # streamed text fragment
    finished = Signal()
    error = Signal(str)

    def __init__(
        self,
        packet_text: str,
        model: str,
        user_context: str = "",
        device_vendor: str = "",
        hostname: str = "",
        parent=None,
    ):
        super().__init__(parent)
        self.packet_text = packet_text
        self.user_context = user_context
        self.device_vendor = device_vendor
        self.hostname = hostname
        self.model = model

    def run(self):
        """Stream LLM analysis of the packet to the token signal."""
        device_section = ""
        if self.device_vendor or self.hostname:
            device_section = "\nDevice under analysis:"
            if self.hostname:
                device_section += f"\n  Hostname : {self.hostname}"
            if self.device_vendor:
                device_section += f"\n  Vendor   : {self.device_vendor}"
            device_section += "\n"

        context_section = (
            f"\nAdditional context from analyst:\n{self.user_context}\n"
            if self.user_context
            else ""
        )
        prompt = (
            f"{SYSTEM_PROMPT}\n{device_section}{context_section}\nPacket:\n{self.packet_text}"
        )
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": True,
        }
        try:
            with requests.post(
                OLLAMA_URL, json=payload, stream=True, timeout=(5, 300)
            ) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not line:
                        continue
                    chunk = json.loads(line)
                    if chunk.get("response"):
                        self.token.emit(chunk["response"])
                    if chunk.get("done"):
                        break
        except requests.exceptions.ConnectionError:
            self.error.emit("Ollama not running — start it with: ollama serve")
        except requests.exceptions.ReadTimeout:
            self.error.emit(
                f"Ollama timed out — model '{self.model}' is too slow or not loaded. "
                "Try: ollama pull " + self.model
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.error.emit(str(e))
        finally:
            self.finished.emit()


class AnthropicThread(QThread):
    """Streams packet analysis via the Anthropic API. Emits token by token."""

    token = Signal(str)
    finished = Signal()
    error = Signal(str)

    def __init__(
        self,
        packet_text: str,
        model: str,
        api_key: str = "",
        user_context: str = "",
        device_vendor: str = "",
        hostname: str = "",
        parent=None,
    ):
        super().__init__(parent)
        self.packet_text = packet_text
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.user_context = user_context
        self.device_vendor = device_vendor
        self.hostname = hostname

    def run(self):
        """Stream analysis from the Anthropic API to the token signal."""
        try:
            import anthropic  # pylint: disable=import-outside-toplevel
        except ImportError:
            self.error.emit(
                "anthropic package not installed — run: pip install anthropic"
            )
            self.finished.emit()
            return

        if not self.api_key:
            self.error.emit(
                "No Anthropic API key — set ANTHROPIC_API_KEY or enter it in the UI."
            )
            self.finished.emit()
            return

        device_section = ""
        if self.device_vendor or self.hostname:
            device_section = "\nDevice under analysis:"
            if self.hostname:
                device_section += f"\n  Hostname : {self.hostname}"
            if self.device_vendor:
                device_section += f"\n  Vendor   : {self.device_vendor}"
            device_section += "\n"

        context_section = (
            f"\nAdditional context from analyst:\n{self.user_context}\n"
            if self.user_context
            else ""
        )
        user_message = (
            f"{device_section}{context_section}\nPacket:\n{self.packet_text}"
        )

        try:
            client = anthropic.Anthropic(api_key=self.api_key)
            with client.messages.stream(
                model=self.model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            ) as stream:
                for text in stream.text_stream:
                    self.token.emit(text)
        except anthropic.AuthenticationError:
            self.error.emit("Invalid Anthropic API key.")
        except anthropic.RateLimitError:
            self.error.emit("Anthropic rate limit reached — try again shortly.")
        except anthropic.APIConnectionError:
            self.error.emit("Cannot reach Anthropic API — check your network.")
        except anthropic.APIStatusError as e:
            self.error.emit(f"Anthropic API error {e.status_code}: {e.message}")
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.error.emit(str(e))
        finally:
            self.finished.emit()
