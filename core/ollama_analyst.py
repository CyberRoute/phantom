"""
Ollama integration — streams LLM analysis of a captured packet.
"""

import json

import requests
from PySide6.QtCore import QThread, Signal  # pylint: disable=E0611

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.2:1b"

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
        user_context: str = "",
        model: str = DEFAULT_MODEL,
        parent=None,
    ):
        super().__init__(parent)
        self.packet_text = packet_text
        self.user_context = user_context
        self.model = model

    def run(self):
        """Stream LLM analysis of the packet to the token signal."""
        context_section = (
            f"\nAdditional context from analyst:\n{self.user_context}\n"
            if self.user_context
            else ""
        )
        prompt = f"{SYSTEM_PROMPT}\n{context_section}\nPacket:\n{self.packet_text}"
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
