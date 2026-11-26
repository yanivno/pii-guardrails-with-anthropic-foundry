"""
PoC: Azure AI Content Safety guardrail for Claude models in Microsoft Foundry, optionally layered
with the 2b Azure AI Language PII screen.

APIs used (api-version 2024-09-01, GA):
  POST {CONTENT_SAFETY_ENDPOINT}/contentsafety/text:shieldPrompt             Prompt Shields
  POST {CONTENT_SAFETY_ENDPOINT}/contentsafety/text:analyze                  Hate, SelfHarm, Sexual, Violence + blocklists
  POST {CONTENT_SAFETY_ENDPOINT}/contentsafety/text:detectProtectedMaterial  known text in completions
  Docs: https://learn.microsoft.com/azure/ai-services/content-safety/overview

Flow:
  1. Prompt (+ optional documents) -> Prompt Shields + harm categories + blocklists -> allow | block
     then, if PII is enabled, the 2b PII screen        -> allow | redact | block
  2. Claude in Foundry (only sees allowed / redacted input)
  3. Answer -> harm categories + blocklists + protected material -> allow | block
     then, if PII is enabled, the 2b PII screen        -> allow | redact | block
  Content Safety has no redaction; its findings always block. Any screening error fails closed.

Install:
  pip install -r requirements.txt

Settings are read from a .env file beside this script (exported variables take precedence):
  CONTENT_SAFETY_ENDPOINT      https://<content-safety-or-foundry-resource>.cognitiveservices.azure.com
  CONTENT_SAFETY_KEY           optional; if not set, Microsoft Entra ID (DefaultAzureCredential) is used
  CONTENT_SAFETY_API_VERSION   default 2024-09-01
  HARM_SEVERITY_THRESHOLD      2 | 4 (default) | 6; block when any category reaches it (4 = medium and high)
  BLOCKLIST_NAMES              optional, comma-separated custom blocklists already created on the resource
  PROMPT_SHIELDS               true (default) | false
  PROTECTED_MATERIAL           true (default) | false
  FOUNDRY_BASE_URL             https://<foundry-resource>.services.ai.azure.com/anthropic
  FOUNDRY_API_KEY              optional; if not set, Microsoft Entra ID is used
  CLAUDE_DEPLOYMENT            e.g. claude-sonnet-4-6
  LANGUAGE_ENDPOINT            optional; set to also run the 2b PII screen (uses ../2b-language-pii)
  LANGUAGE_KEY, PII_*, INPUT_PII_MODE, OUTPUT_PII_MODE   same meaning and defaults as in 2b
  TLS_MAX_VERSION              optional; set to 1.2 if your network breaks TLS 1.3 handshakes
"""

from __future__ import annotations

import logging
import os
import ssl
import sys
from dataclasses import dataclass, field
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("content-safety-guard")

API_VERSION = "2024-09-01"
MAX_TEXT_CHARS = 10_000             # analyze text, Prompt Shields prompt, protected material
MAX_SHIELD_DOCS = 5                 # Prompt Shields: up to 5 documents...
MAX_SHIELD_DOC_CHARS = 10_000       # ...with a total of 10K characters per request
PROTECTED_MATERIAL_MIN_CHARS = 110  # the detector targets completions of at least 110 characters
HARM_CATEGORIES = ("Hate", "SelfHarm", "Sexual", "Violence")
COGNITIVE_SCOPE = "https://cognitiveservices.azure.com/.default"
FOUNDRY_SCOPE = "https://ai.azure.com/.default"
PII_DIR = Path(__file__).resolve().parent.parent / "2b-language-pii"


class ScreeningError(RuntimeError):
    """Content Safety could not screen the text. Treated as a block (fail closed)."""


def tls12_context() -> ssl.SSLContext:
    """TLS 1.2 cap for networks that break TLS 1.3 handshakes; certificates are still verified."""
    import certifi
    context = ssl.create_default_context(cafile=certifi.where())
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    return context


class _Tls12Adapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = tls12_context()
        super().init_poolmanager(*args, **kwargs)


def load_pii_module():
    """Import the 2b PII guard so 2c reuses its screener instead of duplicating it."""
    if str(PII_DIR) not in sys.path:
        sys.path.insert(0, str(PII_DIR))
    import claude_pii_guard
    return claude_pii_guard


def chunk_text(text: str, size: int = MAX_TEXT_CHARS) -> list[str]:
    """Split into <=size chunks, preferring whitespace, so the chunks re-join to the original text."""
    chunks, start = [], 0
    while start < len(text):
        end = min(start + size, len(text))
        if end < len(text):
            cut = max(text.rfind(ws, start, end) for ws in (" ", "\n", "\t"))
            if cut > start:
                end = cut + 1
        chunks.append(text[start:end])
        start = end
    return chunks


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


@dataclass
class CheckResult:
    direction: str                      # input | output
    decision: str                       # allow | redact | block
    original: str
    safe_text: str | None               # None when blocked
    reasons: list[str] = field(default_factory=list)   # e.g. PromptAttack, Hate:4, Blocklist:x, PII:Email
    safe_documents: list[str] = field(default_factory=list)


@dataclass
class GuardedResponse:
    prompt_check: CheckResult
    output_check: CheckResult | None    # None if Claude was not called
    answer: str                         # what the user sees


class ContentSafetyClient:
    """Thin REST client for the Azure AI Content Safety text APIs."""

    def __init__(self, endpoint: str, api_key: str | None = None, api_version: str = API_VERSION,
                 timeout: int = 20, tls12: bool = False):
        self.base = f"{endpoint.rstrip('/')}/contentsafety/text:"
        self.api_key = api_key
        self.api_version = api_version
        self.timeout = timeout
        self._session = None
        if tls12:
            self._session = requests.Session()
            self._session.mount("https://", _Tls12Adapter())
        self._credential = None
        if not api_key:
            from azure.identity import DefaultAzureCredential
            self._credential = DefaultAzureCredential()

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Ocp-Apim-Subscription-Key"] = self.api_key
        else:
            h["Authorization"] = f"Bearer {self._credential.get_token(COGNITIVE_SCOPE).token}"
        return h

    def _post(self, operation: str, body: dict) -> dict:
        try:
            post = self._session.post if self._session else requests.post
            r = post(self.base + operation, params={"api-version": self.api_version},
                     headers=self._headers(), json=body, timeout=self.timeout)
        except requests.RequestException as e:
            raise ScreeningError(f"Content Safety {operation} unreachable: {type(e).__name__}") from e
        if r.status_code != 200:
            # The error body can echo submitted text, so only the status and error code are reported.
            code = (getattr(r, "headers", None) or {}).get("x-ms-error-code")
            raise ScreeningError(f"Content Safety {operation} returned HTTP {r.status_code}"
                                 + (f" ({code})" if code else ""))
        try:
            payload = r.json()
        except ValueError as e:
            raise ScreeningError(f"Invalid JSON from Content Safety {operation}") from e
        if not isinstance(payload, dict):
            raise ScreeningError(f"Invalid Content Safety {operation} result")
        return payload

    def analyze_text(self, text: str, blocklists: list[str] | None = None) -> dict:
        body = {"text": text, "categories": list(HARM_CATEGORIES), "outputType": "FourSeverityLevels"}
        if blocklists:
            body |= {"blocklistNames": blocklists, "haltOnBlocklistHit": False}
        return self._post("analyze", body)

    def shield_prompt(self, user_prompt: str, documents: list[str]) -> dict:
        return self._post("shieldPrompt", {"userPrompt": user_prompt, "documents": documents})

    def detect_protected_material(self, text: str) -> dict:
        return self._post("detectProtectedMaterial", {"text": text})


class ContentSafetyScreener:
    """Turns Content Safety results into block reasons. An empty list means the text passed."""

    def __init__(self, client: ContentSafetyClient, harm_threshold: int = 4,
                 blocklists: list[str] | None = None, prompt_shields: bool = True,
                 protected_material: bool = True):
        if harm_threshold not in (2, 4, 6):
            raise ValueError("HARM_SEVERITY_THRESHOLD must be 2, 4, or 6")
        self.client = client
        self.harm_threshold = harm_threshold
        self.blocklists = blocklists
        self.prompt_shields = prompt_shields
        self.protected_material = protected_material

    def screen_input(self, prompt: str, documents: list[str] | None = None) -> list[str]:
        documents = documents or []
        reasons = self._shield(prompt, documents) if self.prompt_shields else []
        for text in (prompt, *documents):
            reasons += self._harm(text)
        return _unique(reasons)

    def screen_output(self, answer: str) -> list[str]:
        reasons = self._harm(answer)
        if self.protected_material:
            reasons += self._protected(answer)
        return _unique(reasons)

    def _harm(self, text: str) -> list[str]:
        reasons = []
        for chunk in chunk_text(text) if text.strip() else []:
            payload = self.client.analyze_text(chunk, self.blocklists)
            analysis, matches = payload.get("categoriesAnalysis"), payload.get("blocklistsMatch") or []
            if not isinstance(analysis, list) or not isinstance(matches, list):
                raise ScreeningError("Incomplete Content Safety analyze result")
            severities = {a.get("category"): a.get("severity") for a in analysis if isinstance(a, dict)}
            if any(type(severities.get(c)) is not int for c in HARM_CATEGORIES):
                raise ScreeningError("Missing harm category severity")
            reasons += [f"{c}:{severities[c]}" for c in HARM_CATEGORIES if severities[c] >= self.harm_threshold]
            for m in matches:
                if not isinstance(m, dict) or not isinstance(m.get("blocklistName"), str):
                    raise ScreeningError("Invalid blocklist match")
                reasons.append(f"Blocklist:{m['blocklistName']}")   # never report the matched item text
        return reasons

    def _shield(self, prompt: str, documents: list[str]) -> list[str]:
        prompt_chunks = chunk_text(prompt) if prompt.strip() else []
        doc_batches: list[list[str]] = []
        for chunk in (c for d in documents if d.strip() for c in chunk_text(d, MAX_SHIELD_DOC_CHARS)):
            if (not doc_batches or len(doc_batches[-1]) == MAX_SHIELD_DOCS
                    or sum(map(len, doc_batches[-1])) + len(chunk) > MAX_SHIELD_DOC_CHARS):
                doc_batches.append([])
            doc_batches[-1].append(chunk)
        reasons = []
        for i in range(max(len(prompt_chunks), len(doc_batches))):
            user_prompt = prompt_chunks[i] if i < len(prompt_chunks) else ""
            docs = doc_batches[i] if i < len(doc_batches) else []
            payload = self.client.shield_prompt(user_prompt, docs)
            if user_prompt:
                attack = (payload.get("userPromptAnalysis") or {}).get("attackDetected")
                if type(attack) is not bool:
                    raise ScreeningError("Incomplete Prompt Shields user prompt result")
                if attack:
                    reasons.append("PromptAttack")
            analyses = payload.get("documentsAnalysis") or []
            if not isinstance(analyses, list) or len(analyses) != len(docs):
                raise ScreeningError("Unexpected Prompt Shields document results")
            for a in analyses:
                attack = a.get("attackDetected") if isinstance(a, dict) else None
                if type(attack) is not bool:
                    raise ScreeningError("Incomplete Prompt Shields document result")
                if attack:
                    reasons.append("DocumentAttack")
        return reasons

    def _protected(self, text: str) -> list[str]:
        if len(text.strip()) < PROTECTED_MATERIAL_MIN_CHARS:
            return []
        chunks = chunk_text(text)
        if len(chunks) > 1 and len(chunks[-1]) < PROTECTED_MATERIAL_MIN_CHARS:
            chunks[-1] = text[-PROTECTED_MATERIAL_MIN_CHARS:]   # overlap so the tail is long enough to check
        for chunk in chunks:
            analysis = self.client.detect_protected_material(chunk).get("protectedMaterialAnalysis")
            detected = analysis.get("detected") if isinstance(analysis, dict) else None
            if type(detected) is not bool:
                raise ScreeningError("Incomplete protected material result")
            if detected:
                return ["ProtectedMaterial"]
        return []


class GuardedClaude:
    """Calls Claude in Foundry with Content Safety (and optional PII) checks on input and answer."""

    def __init__(self, screener: ContentSafetyScreener, base_url: str, deployment: str,
                 api_key: str | None = None, pii=None, input_pii_mode: str = "block",
                 output_pii_mode: str = "redact", max_tokens: int = 1024, claude=None, tls12: bool = False):
        for m in (input_pii_mode, output_pii_mode):
            if m not in ("block", "redact"):
                raise ValueError("PII modes must be 'block' or 'redact'")
        if claude is None:
            import httpx
            from anthropic import AnthropicFoundry
            http_client = httpx.Client(verify=tls12_context(), timeout=60) if tls12 else None
            if api_key:
                claude = AnthropicFoundry(api_key=api_key, base_url=base_url, http_client=http_client)
            else:
                from azure.identity import DefaultAzureCredential, get_bearer_token_provider
                claude = AnthropicFoundry(
                    azure_ad_token_provider=get_bearer_token_provider(DefaultAzureCredential(), FOUNDRY_SCOPE),
                    base_url=base_url, http_client=http_client)
        self.claude = claude
        self.screener = screener
        self.deployment = deployment
        self.pii = pii                  # a 2b PiiScreener, or None for Content Safety only
        self.input_pii_mode = input_pii_mode
        self.output_pii_mode = output_pii_mode
        self.max_tokens = max_tokens
        self._errors: tuple[type[Exception], ...] = (ScreeningError,)
        if pii is not None:
            pii_module = load_pii_module()
            self._errors += (pii_module.PiiScreeningError,)
            self._placeholder_re = pii_module.PLACEHOLDER_RE

    # ---------- step 1: prompt and documents ----------
    def check_prompt(self, prompt: str, documents: list[str] | None = None) -> CheckResult:
        documents = list(documents or [])
        reasons = self.screener.screen_input(prompt, documents)
        if reasons:
            return CheckResult("input", "block", prompt, None, reasons)
        if self.pii is None:
            return CheckResult("input", "allow", prompt, prompt, safe_documents=documents)
        scans = [self.pii.scan(t) for t in (prompt, *documents)]
        pii_reasons = _unique([f"PII:{c}" for findings, _ in scans for c in sorted({f.category for f in findings})])
        if not pii_reasons:
            return CheckResult("input", "allow", prompt, prompt, safe_documents=documents)
        if self.input_pii_mode == "block":
            return CheckResult("input", "block", prompt, None, pii_reasons)
        return CheckResult("input", "redact", prompt, scans[0][1], pii_reasons, [r for _, r in scans[1:]])

    # ---------- step 3: answer ----------
    def check_output(self, answer: str) -> CheckResult:
        reasons = self.screener.screen_output(answer)
        if reasons:
            return CheckResult("output", "block", answer, None, reasons)
        if self.pii is None:
            return CheckResult("output", "allow", answer, answer)
        findings, _ = self.pii.scan(answer)
        # Ignore placeholders from the redacted prompt that Claude echoed back.
        findings = [f for f in findings if not self._placeholder_re.match(f.text.strip())]
        if not findings:
            return CheckResult("output", "allow", answer, answer)
        pii_reasons = [f"PII:{c}" for c in sorted({f.category for f in findings})]
        if self.output_pii_mode == "block":
            return CheckResult("output", "block", answer, None, pii_reasons)
        safe = answer
        for f in sorted(findings, key=lambda x: x.offset, reverse=True):
            safe = safe[:f.offset] + f"[REDACTED:{f.category}]" + safe[f.offset + f.length:]
        return CheckResult("output", "redact", answer, safe, pii_reasons)

    # ---------- end to end ----------
    def ask(self, prompt: str, documents: list[str] | None = None) -> GuardedResponse:
        # 1. Prompt and document checks
        try:
            p = self.check_prompt(prompt, documents)
        except self._errors as e:
            log.error("Prompt screening failed, blocking: %s", e)
            p = CheckResult("input", "block", prompt, None)
            return GuardedResponse(p, None, "Your request could not be screened, so it was not sent.")
        self._audit(p)
        if p.decision == "block":
            return GuardedResponse(p, None, "Your request was not sent because it was flagged ("
                                   + ", ".join(p.reasons) + ").")

        # 2. Claude: documents go in separate, labelled content blocks ahead of the prompt.
        content = [{"type": "text", "text": f'<document index="{i}">\n{d}\n</document>'}
                   for i, d in enumerate(p.safe_documents, 1)]
        content.append({"type": "text", "text": p.safe_text})
        kwargs = dict(model=self.deployment, max_tokens=self.max_tokens,
                      messages=[{"role": "user", "content": content if p.safe_documents else p.safe_text}])
        if p.decision == "redact":
            kwargs["system"] = ("Some personal data in the user's message was replaced by placeholders such as "
                                "[PERSON-1] or [EMAIL-2]. Treat them as the real values, keep them as written, "
                                "and never guess or invent personal data.")
        resp = self.claude.messages.create(**kwargs)
        if getattr(resp, "stop_reason", None) == "refusal":
            o = CheckResult("output", "block", "", None, ["ClaudeRefusal"])
            self._audit(o)
            return GuardedResponse(p, o, "Claude declined to answer this request.")
        answer = "".join(b.text for b in resp.content if b.type == "text")

        # 3. Answer check
        try:
            o = self.check_output(answer)
        except self._errors as e:
            log.error("Answer screening failed, withholding answer: %s", e)
            o = CheckResult("output", "block", answer, None)
            return GuardedResponse(p, o, "The answer could not be screened, so it was withheld.")
        self._audit(o)
        if o.decision == "block":
            return GuardedResponse(p, o, "The answer was withheld because it was flagged ("
                                   + ", ".join(o.reasons) + ").")
        return GuardedResponse(p, o, o.safe_text)

    @staticmethod
    def _audit(r: CheckResult) -> None:
        # Reasons only, never the screened text or matched values.
        log.info("Guard %s decision=%s reasons=%s", r.direction, r.decision, r.reasons)


def _env_bool(name: str, default: bool) -> bool:
    value = (os.getenv(name) or "").strip().lower()
    if not value:
        return default
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} must be true or false")


def build_from_env() -> GuardedClaude:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().with_name(".env"), override=False)
    missing = [n for n in ("CONTENT_SAFETY_ENDPOINT", "FOUNDRY_BASE_URL", "CLAUDE_DEPLOYMENT")
               if not os.getenv(n, "").strip()]
    if missing:
        raise ValueError("Missing required 2c settings: " + ", ".join(missing))
    max_tls = os.getenv("TLS_MAX_VERSION", "").strip()
    if max_tls not in ("", "1.2"):
        raise ValueError("TLS_MAX_VERSION supports only 1.2")
    tls12 = max_tls == "1.2"
    blocklists = [b.strip() for b in os.getenv("BLOCKLIST_NAMES", "").split(",") if b.strip()] or None
    screener = ContentSafetyScreener(
        ContentSafetyClient(os.environ["CONTENT_SAFETY_ENDPOINT"], os.getenv("CONTENT_SAFETY_KEY") or None,
                            os.getenv("CONTENT_SAFETY_API_VERSION") or API_VERSION, tls12=tls12),
        harm_threshold=int(os.getenv("HARM_SEVERITY_THRESHOLD") or "4"),
        blocklists=blocklists,
        prompt_shields=_env_bool("PROMPT_SHIELDS", True),
        protected_material=_env_bool("PROTECTED_MATERIAL", True),
    )
    pii = None
    if os.getenv("LANGUAGE_ENDPOINT", "").strip():
        m = load_pii_module()
        categories = [c.strip() for c in os.getenv("PII_CATEGORIES", "").split(",") if c.strip()] or None
        pii = m.PiiScreener(
            m.LanguagePiiClient(os.environ["LANGUAGE_ENDPOINT"], os.getenv("LANGUAGE_KEY") or None,
                                os.getenv("PII_API_VERSION") or "2025-11-15-preview", tls12=tls12),
            redaction_policy=os.getenv("PII_POLICY") or "entityMask",
            language=os.getenv("PII_LANGUAGE") or "en",
            min_confidence=float(os.getenv("PII_MIN_CONFIDENCE") or "0.8"),
            categories=categories,
        )
    return GuardedClaude(screener, os.environ["FOUNDRY_BASE_URL"], os.environ["CLAUDE_DEPLOYMENT"],
                         api_key=os.getenv("FOUNDRY_API_KEY") or None, pii=pii,
                         input_pii_mode=(os.getenv("INPUT_PII_MODE") or "block").lower(),
                         output_pii_mode=(os.getenv("OUTPUT_PII_MODE") or "redact").lower(), tls12=tls12)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    for noisy in ("httpx", "azure"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    guard = build_from_env()
    s = guard.screener
    pii_status = f"{guard.input_pii_mode}/{guard.output_pii_mode}" if guard.pii else "off"
    print(f"Harm threshold: {s.harm_threshold} | Prompt Shields: {s.prompt_shields} | "
          f"Protected material: {s.protected_material} | Blocklists: {s.blocklists or '-'} | "
          f"PII (input/output): {pii_status}. Type 'exit' to quit.\n")
    while True:
        prompt = input("You: ").strip()
        if prompt.lower() in ("exit", "quit"):
            break
        if not prompt:
            continue
        r = guard.ask(prompt)
        print(f"  [prompt] {r.prompt_check.decision} {r.prompt_check.reasons}")
        if r.prompt_check.decision == "redact":
            print(f"  [sent to Claude] {r.prompt_check.safe_text}")
        if r.output_check:
            print(f"  [output] {r.output_check.decision} {r.output_check.reasons}")
        print(f"Claude: {r.answer}\n")
