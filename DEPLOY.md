# Deploying Sentinel (free tiers, no card)

Three pieces: **backend** (FastAPI on Hugging Face Spaces), **frontend** (Next.js on Vercel),
and optionally a **database** (Supabase Postgres). Deploy the backend first, then point the
frontend at it.

> You (not Claude) do the browser steps — creating accounts and pasting secrets. Never put a
> key in the repo; set each as a secret in the host's dashboard. `.env` is gitignored.

---

## 1. Backend → Hugging Face Spaces (Docker)

The repo's `README.md` already has the HF Space frontmatter (`sdk: docker`, `app_port: 7860`)
and the `Dockerfile` builds `api.py` with the slim deps in `requirements-api.txt`.

1. Sign in at <https://huggingface.co> → **New Space** → SDK **Docker** → **Blank** → Public.
2. Add the Space as a git remote and push (username + an access token as the password):
   ```
   git remote add space https://huggingface.co/spaces/<you>/sentinel-api
   git push space main
   ```
3. In the Space: **Settings → Variables and secrets → New secret**, add:
   - **`GEMINI_API_KEY`** — required (report parsing, correlation, fixes, summaries).
   - **`REDCELL_GEMINI_KEY`** — optional; a *separate* Gemini key so the AI red-team's heavy
     usage doesn't drain the main quota. Falls back to `GEMINI_API_KEY` if unset.
   - **`DATABASE_URL`** — optional; your Supabase Postgres URI (see §3). Without it, scans
     persist to disk inside the Space (fine for a demo, but not durable across rebuilds).
4. It builds from the `Dockerfile` and serves at `https://<you>-sentinel-api.hf.space`.
5. Test `https://<that-url>/health` → `{"status":"ok"}`.

*Note: a free Space sleeps when idle; the first request after a nap takes a few seconds to wake.*

---

## 2. Frontend → Vercel (no card)

1. Sign in at <https://vercel.com> with GitHub → **Add New → Project** → import the repo.
2. Set **Root Directory = `frontend`** (the Next.js app lives there).
3. Add an environment variable:
   - **`NEXT_PUBLIC_API_URL`** = your backend URL from step 1 (no trailing slash).
4. Deploy → you get `https://<name>.vercel.app`.

---

## 3. Database → Supabase Postgres (optional, no card)

Durable history + real relational storage (nice resume signal). Without it the app uses disk.

1. <https://supabase.com> → **New project** (free). Set a DB password; pick a nearby region.
2. **Settings → Database → Connection string → URI**. Replace `[YOUR-PASSWORD]`.
3. Add it as the **`DATABASE_URL`** secret on the Hugging Face Space (§1.3) and redeploy.
   The backend auto-detects it and switches from disk to Postgres (creates the tables on boot).

---

## 4. Custom domain → `sentinel.is-a.dev` (free, no card)

Nicer than `*.vercel.app`. After the Vercel app is live:

1. In Vercel: **Project → Settings → Domains → Add** `sentinel.is-a.dev`. Vercel shows a
   CNAME target (usually `cname.vercel-dns.com`).
2. Fork <https://github.com/is-a-dev/register>, add `domains/sentinel.json`:
   ```json
   { "owner": { "username": "drazzaq60-create", "email": "you@example.com" },
     "record": { "CNAME": "cname.vercel-dns.com" } }
   ```
   (Pick another name if `sentinel` is taken.) Open a PR; once merged + DNS propagates, Vercel
   issues the SSL certificate automatically.

---

## 5. After it's up
- Open the Vercel URL, run a web scan or an AI red-team, and check the dashboard.
- CORS is already `*`, so no extra wiring.
- Put the link on your CV / GitHub README / LinkedIn.

### If the frontend can't reach the backend
- Re-check `NEXT_PUBLIC_API_URL` (exact URL, no trailing slash) and **redeploy** the frontend
  (Next.js bakes public env vars at build time).
- Confirm `<backend>/health` works in the browser.
