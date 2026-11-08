"""
ollama_manager.py - Local Ollama AI Client for Android Mobile Forensics
Interfaces with local LLMs (e.g. llama3.2:3b) at http://127.0.0.1:11434.
No cloud dependency. All inferences remain 100% on-premises.
"""

import requests
import json
import time
from typing import Dict, Any, List, Tuple

OLLAMA_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2:3b"


def check_ollama_status() -> Dict[str, Any]:
    """
    Checks if local Ollama daemon is running and returns available models.
    """
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            models = [m.get("name") for m in data.get("models", []) if m.get("name")]
            active = DEFAULT_MODEL if any(DEFAULT_MODEL in m for m in models) else (models[0] if models else DEFAULT_MODEL)
            return {
                "connected": True,
                "endpoint": OLLAMA_BASE_URL,
                "models": models,
                "active_model": active,
                "latency_ms": int(resp.elapsed.total_seconds() * 1000),
                "error": None,
            }
    except Exception as e:
        pass

    return {
        "connected": False,
        "endpoint": OLLAMA_BASE_URL,
        "models": [],
        "active_model": DEFAULT_MODEL,
        "latency_ms": 0,
        "error": "Ollama service offline. Run 'ollama serve' in terminal to enable AI interpretation.",
    }


def query_ollama_inference(
    prompt: str,
    model: str = DEFAULT_MODEL,
    system_instruction: str = "",
    timeout: int = 120
) -> Tuple[bool, str, int]:
    """
    Calls local Ollama generate API.
    Returns: (success, response_text, duration_ms)
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }
    if system_instruction:
        payload["system"] = system_instruction

    start_time = time.time()
    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json=payload,
            timeout=timeout
        )
        duration_ms = int((time.time() - start_time) * 1000)
        if resp.status_code == 200:
            res_json = resp.json()
            return True, res_json.get("response", ""), duration_ms
        return False, f"Ollama HTTP {resp.status_code}: {resp.text}", duration_ms
    except requests.exceptions.Timeout:
        return False, f"Ollama generation timed out after {timeout} seconds.", int((time.time() - start_time) * 1000)
    except Exception as e:
        return False, f"Ollama communication error: {str(e)}", int((time.time() - start_time) * 1000)

