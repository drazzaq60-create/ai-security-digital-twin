# Threat Model — Sentinel Security

This is a short, honest threat model for the part of Sentinel that matters most from a
security standpoint: **an untrusted security report is fed into an LLM.** It states what the
system trusts, what an attacker could try, what defends against it, and — deliberately — what
is **not** defended. Results quoted here come from the eval harnesses in this repo
(`redteam_eval.py`, `redteam_eval_e2e.py`) and can be reproduced.

---

## 1. Scope

In scope: the report-ingestion pipeline — a user uploads a scan report (or runs the built-in
light scan), and the text is parsed, analysed, and summarised, some of it by an LLM (Google
Gemini). This document focuses on **prompt injection via uploaded report content**
(OWASP LLM Top 10 — **LLM01**).

Out of scope (portfolio project, single-user, no auth): multi-tenant isolation, account
security, DoS/rate-limiting, and the security of the Gemini API itself.

---

## 2. Trust boundaries

| Component | Trusted? | Notes |
|---|---|---|
| The user / analyst | Trusted | Single operator; they choose what to upload. |
| **Uploaded report text** | **UNTRUSTED** | May be attacker-authored. This is the key boundary. |
| **Live-scan target's responses** | **UNTRUSTED** | Headers/banners are attacker-controllable. |
| Deterministic parsers (`deterministic_ingest.py`) | Trusted code | No LLM prompt is built, so injection can't act. |
| LLM (Gemini) | Semi-trusted | Follows instructions; can be manipulated by injected text. |
| System/task prompts (in our code) | Trusted | The instructions we *intend* the model to follow. |

The core risk: **untrusted report text crosses into a trusted LLM prompt.** If the model can't
tell our instructions from the attacker's, a malicious report can change the tool's behaviour.

---

## 3. Assets & attacker goals

An attacker who can get a crafted report analysed might try to:

1. **Suppress real findings** — make the tool report a vulnerable host as clean (hide risk).
2. **Force false positives / a "safe" verdict** — same effect, different wording.
3. **Exfiltrate the system prompt** — recover our instructions to craft better attacks.
4. **Hijack the output** — make the tool emit attacker-chosen text instead of analysis.

Impact is *integrity of the analysis* — a security tool that can be told to lie is worse than
no tool, because it manufactures false confidence.

---

## 4. Controls (defence-in-depth)

No single control is trusted to be complete; they layer.

| Layer | Control | Defends against | Limits |
|---|---|---|---|
| **L0** | Deterministic parsers for known formats | Everything — no LLM prompt is built from the report | Only covers known formats (Nmap/Nessus/ZAP/Wazuh/SSL). |
| **L1** | `scan_injection()` — heuristic detector, surfaced to the user | Visibility into known injection classes | Heuristic; evaded by obfuscation (see §5). Never silently drops data. |
| **L2** | `harden_prompt()` + `INJECTION_DEFENSE` — delimiter-wrapping + a preamble telling the model the report is data | The model obeying instructions inside the report | Not a proof; depends on model behaviour. |
| **L3** | `check_output()` — post-hoc scan for hijack / prompt-leak markers | A response that leaked the prompt or was clearly hijacked | Pattern-based; catches obvious cases only. |
| **L4** | `redteam_eval.py` / `redteam_eval_e2e.py` — measurement | Nothing directly — it *measures* L1/L2 so claims stay honest | Fixed local set; not adversarially adaptive. |

**Design principle:** deterministic code computes the facts (parsing, graph, scoring); the LLM
only parses unknown formats, explains, and recommends. That shrinks the surface where injection
can do damage — a poisoned report can't alter the attack-graph math, only the LLM-written prose.

---

## 5. What is measured (honestly)

**Detector (L1)** — `redteam_eval.py`, 23 attacks + 12 benign:
- **Core classes: 93% recall** (direct overrides, suppression, probes, markers, Base64,
  Roman-Urdu, zero-width evasion).
- **Adaptive evasions: 0% recall** — leetspeak, homoglyphs, letter-spacing, real non-English
  script, and pure paraphrase all defeat the regex detector. **This is expected**; a heuristic
  cannot win an obfuscation arms race.
- **False-positive rate: ~8%** (one realistic UI-string FP is left in on purpose, so the number
  is honest rather than a manufactured zero).

**End-to-end (L2)** — `redteam_eval_e2e.py`, real Gemini calls:
- **Naive prompt (no guardrails): 14% attack-success-rate.** A context-confusion attack that
  fakes "END OF REPORT / NEW TASK FROM SYSTEM" fooled the unprotected prompt into dropping a
  real finding.
- **Hardened prompt (L2): 0%.** The explicit `<<<REPORT>>> … <<<END REPORT>>>` delimiters
  removed the ambiguity and defended it.
- Caveat: small set, and a strong base model already resists the simpler injections — so L2's
  measurable value here is on *structural* attacks. The layer is defence-in-depth, not a proof.

---

## 6. Residual risk (NOT defended)

Stated plainly so the claims never outrun the evidence:

- **Obfuscated / adaptive injection** evades L1 (see §5). Mitigation today is L2 only.
- **Semantic paraphrase** (no trigger words at all) is not detected — needs ML/semantic
  detection, which is future work, not present.
- **Non-English / mixed-script** injection beyond Roman-Urdu is largely undetected.
- **Indirect injection** carried inside otherwise-valid fields is only partly covered.
- **Model-dependent defence:** L2's effectiveness rides on the model; a weaker or self-hosted
  model could be more vulnerable, and results can drift as models change.
- **Confidentiality:** report text is sent to a third-party LLM (Gemini). Don't upload
  confidential data on the free tier. Deterministic parsing (L0) avoids the LLM entirely for
  known formats.
- **L3** catches only obvious hijack/leak markers, not subtle manipulation.

---

## 7. Assumptions

- Single trusted operator; no authentication or multi-tenant model.
- Synthetic/sanitised data only; no real secrets in the repo (`.env` is gitignored).
- The live scan is used only against **authorised** targets (enforced by a UI acknowledgement,
  not by the tool — the operator is accountable).

---

## 8. Next steps

- Grow the red-team set and add adaptive mutation (garak / PyRIT style).
- Add normalisation (de-leet, homoglyph folding) to lift L1 on some adaptive classes, and
  explore a small semantic classifier for paraphrase.
- Broaden multilingual coverage beyond Roman-Urdu.

*This model is deliberately modest: it claims defence-in-depth with measured effect on known
and structural attacks, and it is explicit about the classes it does not yet stop.*
