"""
Ollama integration — streams LLM analysis of a captured packet.
"""

import json

import requests
from PySide6.QtCore import QThread, Signal  # pylint: disable=E0611

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "deepseek-r1:1.5b"

SYSTEM_PROMPT = """You are a network security analyst.
You will be given a decoded network packet captured during a MITM session.
Provide a concise analysis covering:
- What protocol/service this traffic belongs to
- What the two endpoints are doing
- Any security-relevant observations (credentials, sensitive data, unusual behaviour)
- A one-line risk assessment (Low / Medium / High)
Keep the response short and factual. No preamble."""


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
                OLLAMA_URL, json=payload, stream=True, timeout=60
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
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.error.emit(str(e))
        finally:
            self.finished.emit()
