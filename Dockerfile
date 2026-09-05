# Backend (FastAPI) container — works on Hugging Face Spaces (free, no card), Render, Railway, Fly, etc.
FROM python:3.11-slim

WORKDIR /app

# install only the slim API deps (no chromadb/streamlit/etc.)
COPY requirements-api.txt .
RUN pip install --no-cache-dir -r requirements-api.txt

# app code (see .dockerignore for what's excluded)
COPY . .

# HF Spaces expects 7860; other hosts inject $PORT. Respect $PORT, default to 7860.
ENV PORT=7860
EXPOSE 7860
CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port ${PORT:-7860}"]
