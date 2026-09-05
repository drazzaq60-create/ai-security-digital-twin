# Deploying Sentinel (free tiers)

Two pieces: the **backend** (FastAPI) and the **frontend** (Next.js). Deploy the backend
first, then point the frontend at it.

> You (not Claude) do these steps — they need your accounts and your Gemini API key. Never
> put the key in the repo; set it as a secret in the host's dashboard.

---

## 1. Backend

### Option A — Render (simplest; uses `render.yaml`)
1. Go to <https://render.com> and sign in with GitHub.
2. **New → Blueprint** → pick the `ai-security-digital-twin` repo → Render reads `render.yaml`.
3. When prompted, add the secret **`GEMINI_API_KEY`** = your key.
4. Deploy. You get a URL like `https://sentinel-api.onrender.com`.
5. Test it: open `https://<your-url>/health` → should show `{"status":"ok"}`.

*Note: Render's free instance sleeps after ~15 min idle, so the first request after a nap
takes ~50s to wake. Fine for a demo. If Render asks for a credit card, use Option B.*

### Option B — Hugging Face Spaces (free, no card; uses the `Dockerfile`)
1. Sign in at <https://huggingface.co> → **New Space** → SDK **Docker** → **Blank** → Public.
2. Add this Space as a git remote and push (use your HF username + an access token as the password):
   ```
   git remote add space https://huggingface.co/spaces/<you>/sentinel-api
   git push space main
   ```
3. In the Space: **Settings → Variables and secrets → New secret** → `GEMINI_API_KEY` = your key.
4. It builds from the `Dockerfile` and serves at `https://<you>-sentinel-api.hf.space`.
5. Test `https://<that-url>/health`.

---

## 2. Frontend (Vercel — free, no card)
1. Sign in at <https://vercel.com> with GitHub → **Add New → Project** → import the repo.
2. Set **Root Directory = `frontend`** (important — the Next.js app lives there).
3. Add an environment variable:
   - **`NEXT_PUBLIC_API_URL`** = your backend URL from step 1 (e.g. `https://sentinel-api.onrender.com`) — no trailing slash.
4. Deploy. You get a URL like `https://sentinel.vercel.app` — that's your shareable link.

---

## 3. After both are up
- Open the Vercel URL, upload a report (try `sample_data/`), and Run Analysis.
- The backend already allows all origins (CORS `*`), so no extra wiring is needed.
- Put the Vercel link on your CV / GitHub README.

### If the frontend can't reach the backend
- Re-check `NEXT_PUBLIC_API_URL` (must be the exact backend URL, no trailing slash) and
  redeploy the frontend (env vars apply at build time).
- Confirm `<backend>/health` works in the browser.
