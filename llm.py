# llm.py
# LLM + embeddings layer, all via Gemini (free tier, with automatic model fallback).

import os
import time
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

# Transient API conditions worth retrying (free-tier demand spikes, rate limits) vs. a hard
# error like 404 (model gone) which should fail straight to the next model.
_TRANSIENT = ("503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED", "overloaded", "high demand")


def _is_transient(e) -> bool:
    s = str(e)
    return any(t in s for t in _TRANSIENT)

# --- Chat models: rotate through these; each has its OWN separate free quota ---
# Default order favours the more capable models (used for reasoning-heavy tasks
# like correlation).
# The "-latest" aliases always resolve to the current flash model, so this list never
# goes stale when Google rotates versions; the pinned 3.5 models are explicit fallbacks.
GEMINI_MODELS = [
    "gemini-flash-latest",
    "gemini-3.5-flash",
    "gemini-flash-lite-latest",
    "gemini-3.5-flash-lite",
]

# Fast order: lightweight-first, for high-volume structured tasks (report parsing,
# per-report fixes). The lite model is quicker and typically less throttled, so the
# first attempt usually succeeds instead of waiting through the SDK's retry/backoff
# on a busy heavier model.
FAST_MODELS = [
    "gemini-flash-lite-latest",
    "gemini-3.5-flash-lite",
    "gemini-flash-latest",
    "gemini-3.5-flash",
]

# --- Embedding models: turn text into search vectors (no local download needed) ---
EMBED_MODELS = [
    "gemini-embedding-001",
    "text-embedding-004",
]

_client = None  # lazily created so the app can boot without a key (features fail at call time)
_embed_model = None  # remembered once we find one that works


def _gemini_client():
    """Create the Gemini client on first use. Raises a clear error if no key is set."""
    global _client
    if _client is None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is not set. Set it in your environment or .env to use LLM features."
            )
        _client = genai.Client(api_key=api_key)
    return _client


def call_llm(system, user, temperature=0.1, models=None):
    """Try each chat model in order; on any failure (rate limit, etc.) fall back to the next.

    Pass `models` (e.g. FAST_MODELS) to change the preference order per task."""
    client = _gemini_client()
    last_error = None
    for model in (models or GEMINI_MODELS):
        # Retry the same model on a TRANSIENT error (503/429 demand spike) with a short
        # backoff before falling through; a hard error (e.g. 404 model gone) moves on at once.
        for retry in range(3):
            try:
                resp = client.models.generate_content(
                    model=model,
                    contents=user,
                    config=types.GenerateContentConfig(system_instruction=system, temperature=temperature),
                )
                print(f"[llm] answered with: {model}")
                return resp.text
            except Exception as e:
                last_error = e
                if _is_transient(e) and retry < 2:
                    time.sleep(1.5 * (retry + 1))   # 1.5s, then 3s, then try the next model
                    continue
                print(f"[llm] {model} unavailable ({type(e).__name__}) - trying next...")
                break
    raise RuntimeError(f"All Gemini chat models failed. Last error: {last_error}")


def _pick_embed_model():
    """Find the first embedding model that works on this key, and reuse it for the whole run."""
    global _embed_model
    if _embed_model:
        return _embed_model
    client = _gemini_client()
    for m in EMBED_MODELS:
        try:
            client.models.embed_content(model=m, contents="test")
            _embed_model = m
            print(f"[embed] using: {m}")
            return m
        except Exception as e:
            print(f"[embed] {m} unavailable ({type(e).__name__}) - trying next...")
    raise RuntimeError("No Gemini embedding model available.")


def embed_texts(texts):
    """Turn a list of texts into vectors via Gemini's API (nothing to download)."""
    model = _pick_embed_model()
    client = _gemini_client()
    vectors = []
    for t in texts:
        resp = client.models.embed_content(model=model, contents=t)
        vectors.append(resp.embeddings[0].values)
    return vectors
