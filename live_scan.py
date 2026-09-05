# live_scan.py
# A real, self-contained "automatic scan" for a single web target. No external
# binaries (no nmap/zap needed) and stdlib-only, so it runs on any free host.
#
# It performs three passive/light checks against ONE authorized target and returns
# findings in the SAME shape the file parsers emit ({name, host, severity, type,
# evidence, source}), so scan results flow into the exact same pipeline as uploads:
# findings -> fixes -> correlation -> attack-surface graph -> guardrails/export.
#
#   1. TLS certificate + protocol   (expiry, weak version)
#   2. HTTP security headers         (HSTS, CSP, X-Frame-Options, ... + banner leak)
#   3. Common-port exposure          (curated short list, concurrent, tight timeouts)
#
# This is deliberately non-intrusive: no exploitation, no fuzzing, no auth attempts.
# It is dual-use security tooling; the caller must confirm the target is authorized.

import socket
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

USER_AGENT = "Sentinel-Security-Scanner/0.5 (+authorized-assessment)"
CONNECT_TIMEOUT = 3.0     # per TCP connect
HTTP_TIMEOUT = 8.0        # per HTTP request
PORT_TIMEOUT = 1.5        # per port probe

# Cloud metadata endpoints are a classic SSRF target; never let the hosted scanner reach them.
_BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal"}

# Security response headers we expect on a hardened site. (header -> (severity, why))
_EXPECTED_HEADERS = {
    "strict-transport-security": ("Medium", "No HSTS - browser can be downgraded to HTTP (MITM / SSL-strip)."),
    "content-security-policy":   ("Medium", "No Content-Security-Policy - weaker defense against XSS / data injection."),
    "x-frame-options":           ("Low",    "No X-Frame-Options / frame-ancestors - clickjacking risk."),
    "x-content-type-options":    ("Low",    "No X-Content-Type-Options: nosniff - MIME-sniffing risk."),
    "referrer-policy":           ("Info",   "No Referrer-Policy - referrer may leak to third parties."),
}

# host banner headers that disclose stack/version (useful recon for an attacker)
_BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")

# curated short port list: (port, service, severity-if-open, note)
_PORTS = [
    (21,   "FTP",        "Medium", "FTP is often cleartext; prefer SFTP/FTPS."),
    (22,   "SSH",        "Info",   "SSH exposed - ensure key-only auth, no root login."),
    (23,   "Telnet",     "High",   "Telnet is cleartext and should never be internet-facing."),
    (25,   "SMTP",       "Info",   "SMTP exposed - check for open relay / STARTTLS."),
    (445,  "SMB",        "High",   "SMB exposed to the internet is high-risk (worms, ransomware)."),
    (3306, "MySQL",      "High",   "Database port exposed - should not be internet-facing."),
    (3389, "RDP",        "High",   "RDP exposed - frequent brute-force / ransomware entry point."),
    (5432, "PostgreSQL", "High",   "Database port exposed - should not be internet-facing."),
    (6379, "Redis",      "High",   "Redis exposed - often unauthenticated; critical exposure."),
    (8080, "HTTP-alt",   "Info",   "Alternate HTTP port open - verify it's intended."),
]


def _f(name, host, severity, ftype, evidence):
    return {"name": name, "host": host, "severity": severity, "type": ftype,
            "evidence": evidence, "source": "live:web"}


def _normalize(target: str):
    """Return (scheme, host, port, base_url) from loose input like 'example.com',
    'https://example.com', or 'example.com:8443'. Raises ValueError on garbage."""
    t = (target or "").strip()
    if not t:
        raise ValueError("empty target")
    if "://" not in t:
        t = "https://" + t
    u = urlparse(t)
    host = (u.hostname or "").strip()
    if not host:
        raise ValueError("could not parse a hostname from the target")
    if host.lower() in _BLOCKED_HOSTS:
        raise ValueError("target is a blocked internal/metadata endpoint")
    scheme = u.scheme if u.scheme in ("http", "https") else "https"
    port = u.port or (443 if scheme == "https" else 80)
    base = f"{scheme}://{host}" + (f":{u.port}" if u.port else "")
    return scheme, host, port, base


def _check_tls(host, port):
    """Inspect the TLS certificate + negotiated protocol. Returns list of findings."""
    out = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                proto = ss.version()  # e.g. 'TLSv1.3'
    except ssl.SSLCertVerificationError as e:
        return [_f("TLS certificate does not validate", host, "High", "tls",
                   f"Certificate verification failed: {getattr(e, 'reason', e)}")]
    except (socket.timeout, ConnectionRefusedError, OSError):
        return []  # no TLS service here; header check will report http-only if relevant

    # Protocol strength
    if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        out.append(_f(f"Weak TLS protocol ({proto})", host, "Medium", "tls",
                      f"Server negotiated {proto}; TLS 1.2+ should be required."))

    # Certificate expiry
    na = cert.get("notAfter") if cert else None
    if na:
        try:
            exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                out.append(_f("TLS certificate expired", host, "High", "tls",
                              f"Certificate expired {-days} day(s) ago ({na})."))
            elif days <= 21:
                out.append(_f("TLS certificate expiring soon", host, "Medium", "tls",
                              f"Certificate expires in {days} day(s) ({na})."))
        except ValueError:
            pass
    return out


def _check_http(base_url, host):
    """Fetch the target and inspect security headers. Returns (findings, reached)."""
    out = []
    req = urllib.request.Request(base_url, headers={"User-Agent": USER_AGENT}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            final_url = resp.geturl()
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        # Still got a response with headers - analyze them.
        final_url = base_url
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
    except Exception as e:
        return [_f("Target unreachable over HTTP(S)", host, "Info", "recon",
                   f"Could not fetch {base_url}: {e}")], False

    # Served over plain HTTP (not upgraded to https) is a real exposure.
    if final_url.startswith("http://"):
        out.append(_f("Site served over plaintext HTTP", host, "High", "transport",
                      f"{final_url} did not redirect to HTTPS; traffic is interceptable."))

    for hdr, (sev, why) in _EXPECTED_HEADERS.items():
        if hdr not in headers:
            out.append(_f(f"Missing security header: {hdr}", host, sev, "header", why))

    for hdr in _BANNER_HEADERS:
        if hdr in headers and headers[hdr].strip():
            out.append(_f(f"Version/stack disclosure via '{hdr}'", host, "Info", "recon",
                          f"{hdr}: {headers[hdr]} - aids targeted attacks; consider suppressing."))
    return out, True


def _check_ports(host):
    """Probe a curated short list of ports concurrently. Returns list of findings."""
    out = []

    def probe(entry):
        port, svc, sev, note = entry
        try:
            with socket.create_connection((host, port), timeout=PORT_TIMEOUT):
                return (port, svc, sev, note)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    with ThreadPoolExecutor(max_workers=min(10, len(_PORTS))) as ex:
        for fut in as_completed(ex.submit(probe, e) for e in _PORTS):
            r = fut.result()
            if r:
                port, svc, sev, note = r
                out.append(_f(f"Open port {port}/{svc}", host, sev, "port",
                              f"TCP {port} ({svc}) is reachable. {note}"))
    return out


def run_web_scan(target: str, do_ports: bool = True) -> dict:
    """Run the light web-target scan. Returns a report-shaped dict:
    {name, host, findings:[...], scan:{...}}. Never raises for network issues -
    only for an unparseable target."""
    started = time.time()
    scheme, host, port, base = _normalize(target)

    findings = []
    checks = []
    tls = _check_tls(host, port if scheme == "https" else 443)
    findings += tls
    checks.append("tls")

    http, reached = _check_http(base, host)
    findings += http
    checks.append("http-headers")

    if do_ports:
        findings += _check_ports(host)
        checks.append("ports")

    # If a hardened site returns nothing, say so explicitly rather than looking "empty/failed".
    if not findings and reached:
        findings.append(_f("No obvious misconfigurations found", host, "Info", "recon",
                           "TLS, security headers and common ports looked healthy in this light scan."))

    return {
        "name": f"Live scan: {host}",
        "host": host,
        "findings": findings,
        "scan": {
            "target": base,
            "checks": checks,
            "reached": reached,
            "duration_s": round(time.time() - started, 2),
            "scanner": USER_AGENT,
            "note": "Light, non-intrusive assessment (headers/TLS/port reachability only). "
                    "Not a full vulnerability scan.",
        },
    }
