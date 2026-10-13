# runtime_env.py
# Tells local dev apart from a public deploy, so powerful features (real external
# scanners; scanning private/loopback targets) can default ON locally yet stay OFF
# on a public host — without anyone having to remember a flag.
#
# An explicit env var ALWAYS wins. Only when a flag is unset do we fall back to the
# "on locally, off in the cloud" default.

import os

# Env vars that common hosting platforms set. Their presence = we're on a public host.
_HOST_SIGNALS = (
    "SPACE_ID",              # Hugging Face Spaces
    "RENDER",                # Render
    "RAILWAY_ENVIRONMENT",   # Railway
    "RAILWAY_PROJECT_ID",    # Railway
    "VERCEL",                # Vercel
    "DYNO",                  # Heroku
    "K_SERVICE",             # Google Cloud Run
    "FLY_APP_NAME",          # Fly.io
    "WEBSITE_INSTANCE_ID",   # Azure App Service
    "KUBERNETES_SERVICE_HOST",
)

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def is_public_deploy():
    """True when a known hosting platform's marker env var is present."""
    return any(os.getenv(k) for k in _HOST_SIGNALS)


def env_flag(name, default):
    """Read a boolean env var. Unset -> `default`. Accepts 1/true/yes/on and 0/false/no/off
    (any case); any other value also falls back to `default`."""
    v = os.getenv(name)
    if v is None:
        return default
    v = v.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    return default
