# llm.py
# LLM + embeddings layer, all via Gemini (free tier, with automatic model fallback).

import os
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

# --- Chat models: rotate through these; each has its OWN separate free quota ---
GEMINI_MODELS = [
    "gemini-3.6-flash",
    "gemini-3.7-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-2.5-flash",
]

# --- Embedding models: turn text into search vectors (no local download needed) ---
EMBED_MODELS = [
    "gemini-embedding-001",
    "text-embedding-004",
]

_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
_embed_model = None  # remembered once we find one that works


def call_llm(system, user, temperature=0.1):
    """Try each chat model in order; on any failure (rate limit, etc.) fall back to the next."""
    last_error = None
    for model in GEMINI_MODELS:
        try:
            resp = _client.models.generate_content(
                model=model,
                contents=user,
                config=types.GenerateContentConfig(system_instruction=system, temperature=temperature),
            )
            print(f"[llm] answered with: {model}")
            return resp.text
        except Exception as e:
            print(f"[llm] {model} unavailable ({type(e).__name__}) - trying next...")
            last_error = e
    raise RuntimeError(f"All Gemini chat models failed. Last error: {last_error}")


def _pick_embed_model():
    """Find the first embedding model that works on this key, and reuse it for the whole run."""
    global _embed_model
    if _embed_model:
        return _embed_model
    for m in EMBED_MODELS:
        try:
            _client.models.embed_content(model=m, contents="test")
            _embed_model = m
            print(f"[embed] using: {m}")
            return m
        except Exception as e:
            print(f"[embed] {m} unavailable ({type(e).__name__}) - trying next...")
    raise RuntimeError("No Gemini embedding model available.")


def embed_texts(texts):
    """Turn a list of texts into vectors via Gemini's API (nothing to download)."""
    model = _pick_embed_model()
    vectors = []
    for t in texts:
        resp = _client.models.embed_content(model=model, contents=t)
        vectors.append(resp.embeddings[0].values)
    return vectors
