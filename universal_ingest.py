# universal_ingest.py
# LLM-based UNIVERSAL report reader.
# Give it ANY security report - any tool, any format (text / JSON / XML / CSV) - and it
# extracts a normalized list of findings. This is how we "understand any tool" WITHOUT
# writing a custom parser for every one. (Bespoke parsers stay for speed on common tools;
# this handles everything else.)

import json
import cache
import guardrails
from llm import call_llm, FAST_MODELS

SCHEMA_HINT = (
    'Return ONLY a JSON array. Each item must be: '
    '{"host": "<host or asset, or unknown>", '
    '"type": "service|vulnerability|web|alert|config|other", '
    '"name": "<short finding name>", '
    '"severity": "Critical|High|Medium|Low|Info|Unknown", '
    '"evidence": "<brief quote/detail from the report>"}'
)


_VALID_SEV = {"Critical", "High", "Medium", "Low", "Info", "Unknown"}
_VALID_TYPE = {"service", "vulnerability", "web", "alert", "config", "other"}


def _normalize(item, source_name):
    """Coerce one raw LLM item into a valid, fully-populated finding.

    The model sometimes drops fields, mislabels severity, or returns non-dict junk.
    We never trust it blindly - every finding leaves here with all keys present and
    a severity/type that the UI can actually render."""
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "").strip()
    if not name:
        return None  # a finding with no name is noise, drop it
    sev = str(item.get("severity") or "Unknown").strip().title()
    if sev not in _VALID_SEV:
        sev = "Unknown"
    ftype = str(item.get("type") or "other").strip().lower()
    if ftype not in _VALID_TYPE:
        ftype = "other"
    return {
        "name": name,
        "host": str(item.get("host") or "unknown").strip(),
        "severity": sev,
        "type": ftype,
        "evidence": str(item.get("evidence") or "").strip(),
        "source": source_name,
    }


def extract_findings(raw_report, source_name="unknown_tool", return_meta=False):
    """Use the LLM to turn ANY raw report into a normalized, validated findings list.

    With return_meta=True, also return a Layer-3 output check {ok, reason} that flags
    signs the model was hijacked or leaked its prompt (a successful injection)."""
    ck = cache.key_for(source_name, raw_report)
    cached = cache.get("extract", ck)
    if cached is not None:
        return (cached, {"ok": True, "reason": "cached"}) if return_meta else cached

    # Layer 2 (harden): warn the model that the report is untrusted, and wrap the report
    # text in delimiters so the model treats it as DATA, never as instructions to obey.
    system = guardrails.INJECTION_DEFENSE + (
        "You are a security report parser. Read the raw report below (it may come from any tool "
        "and be in any format) and extract every DISTINCT security finding into a normalized JSON "
        "array. Do NOT invent findings - extract only what is actually present. " + SCHEMA_HINT
    )
    user = f"SOURCE TOOL: {source_name}\n\n" + guardrails.harden_prompt(raw_report)
    raw = call_llm(system, user, models=FAST_MODELS)

    # Layer 3 (check output): did the model get hijacked or leak its prompt?
    out_check = guardrails.check_output(raw)

    try:
        start, end = raw.find("["), raw.rfind("]")
        items = json.loads(raw[start:end + 1]) if start != -1 and end != -1 else []
    except Exception:
        items = []
    if not isinstance(items, list):
        items = []

    cleaned = [n for n in (_normalize(it, source_name) for it in items) if n]
    cache.set("extract", ck, cleaned)
    return (cleaned, out_check) if return_meta else cleaned


if __name__ == "__main__":
    # Demo: parse an SSL report we have NO custom parser for - the LLM handles it anyway.
    with open("sample_data/ssl_report.json", "r", encoding="utf-8") as f:
        raw = f.read()

    print("Extracting findings from an SSL report (no bespoke parser exists for it)...\n")
    findings = extract_findings(raw, source_name="ssl_scanner")
    for x in findings:
        print(f" - [{x.get('host')}] {x.get('name')}  ({x.get('severity')})  |  {x.get('evidence', '')}")
