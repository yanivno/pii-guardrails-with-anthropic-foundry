"""
PoC: PII guardrail for Claude models in Microsoft Foundry, using the Azure AI Language
"Detect and redact PII in text" REST API on BOTH the prompt and the model output.

API used:
  POST {LANGUAGE_ENDPOINT}/language/:analyze-text?api-version=2025-11-15-preview
  kind = "PiiEntityRecognition", with redactionPolicies + confidenceScoreThreshold
  Docs: https://learn.microsoft.com/azure/ai-services/language-service/personally-identifiable-information/how-to/redact-text-pii

Flow:
  1. Prompt  -> PII API -> allow | redact (service redactedText, e.g. [PERSON_1]) | block (Claude not called)
  2. Claude in Foundry (only sees the allowed / redacted prompt)
  3. Output  -> PII API -> allow | redact ([REDACTED:Email]) | block (answer withheld)
  Any screening error fails closed.

Install:
  pip install -r requirements.txt

Settings are read from a .env file beside this script (exported variables take precedence):
  LANGUAGE_ENDPOINT    https://<language-or-foundry-resource>.cognitiveservices.azure.com
  LANGUAGE_KEY         optional; if not set, Microsoft Entra ID (DefaultAzureCredential) is used
  PII_API_VERSION      default 2025-11-15-preview
  FOUNDRY_BASE_URL     https://<foundry-resource>.services.ai.azure.com/anthropic
  FOUNDRY_API_KEY      optional; if not set, Microsoft Entra ID is used
  CLAUDE_DEPLOYMENT    e.g. claude-sonnet-4-6
  INPUT_PII_MODE       block (default) | redact
  OUTPUT_PII_MODE      redact (default) | block
  PII_POLICY           entityMask (default) | characterMask | syntheticReplacement  (prompt redaction)
  PII_LANGUAGE         en (default)
  PII_MIN_CONFIDENCE   0.8 (default)
  PII_CATEGORIES       optional, comma-separated, e.g. Email,PhoneNumber,CreditCardNumber
  TLS_MAX_VERSION      optional; set to 1.2 if your network breaks TLS 1.3 handshakes
"""

from __future__ import annotations

import logging
import os
import re
import ssl
from dataclasses import dataclass, field
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter

log = logging.getLogger("pii-guard")

MAX_CHARS_PER_DOC = 5000   # service limit: 5,120 text elements per document (sync)
MAX_DOCS_PER_CALL = 5      # service limit: 5 documents per PII request (sync)
COGNITIVE_SCOPE = "https://cognitiveservices.azure.com/.default"
FOUNDRY_SCOPE = "https://ai.azure.com/.default"

# Placeholders created by entityMask on the prompt, e.g. [PERSON-1]. Claude may echo them back;
# they are not PII, so the output check ignores them.
PLACEHOLDER_RE = re.compile(r"^\[[A-Z0-9]+[-_]\d+\]$")


class PiiScreeningError(RuntimeError):
    """The PII service could not screen the text. Treated as a block (fail closed)."""


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


@dataclass
class PiiFinding:
    text: str
    category: str
    subcategory: str | None
    confidence: float
    offset: int
    length: int


@dataclass
class ScreenResult:
    direction: str                      # input | output
    decision: str                       # allow | redact | block
    original: str
    safe_text: str | None               # None when blocked
    findings: list[PiiFinding] = field(default_factory=list)

    @property
    def categories(self) -> list[str]:
        return sorted({f.category for f in self.findings})


@dataclass
class GuardedResponse:
    prompt_check: ScreenResult
    output_check: ScreenResult | None   # None if Claude was not called
    answer: str                         # what the user sees


class LanguagePiiClient:
    """Thin REST client for the Azure AI Language PII API (analyze-text, PiiEntityRecognition)."""

    def __init__(self, endpoint: str, api_key: str | None = None,
                 api_version: str = "2025-11-15-preview", timeout: int = 20, tls12: bool = False):
        self.url = f"{endpoint.rstrip('/')}/language/:analyze-text"
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

    def analyze(self, documents: list[dict], parameters: dict) -> dict:
        body = {"kind": "PiiEntityRecognition", "parameters": parameters,
                "analysisInput": {"documents": documents}}
        try:
            post = self._session.post if self._session else requests.post
            r = post(self.url, params={"api-version": self.api_version},
                     headers=self._headers(), json=body, timeout=self.timeout)
        except requests.RequestException as e:
            raise PiiScreeningError(f"PII service unreachable: {type(e).__name__}") from e
        if r.status_code != 200:
            raise PiiScreeningError(f"PII service returned HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError as e:
            raise PiiScreeningError("Invalid JSON from PII service") from e


class PiiScreener:
    """Screens text with the PII API and returns findings plus the service's redacted text."""

    def __init__(self, client: LanguagePiiClient, redaction_policy: str = "entityMask",
                 language: str = "en", min_confidence: float = 0.8,
                 categories: list[str] | None = None):
        self.client = client
        if redaction_policy not in {"entityMask", "characterMask", "syntheticReplacement"}:
            raise ValueError("Unsupported PII redaction policy")
        self.redaction_policy = redaction_policy
        self.language = language
        self.min_confidence = min_confidence
        self.categories = categories

    def _parameters(self) -> dict:
        p = {
            "modelVersion": "latest",
            "stringIndexType": "UnicodeCodePoint",  # offsets match Python string indexing
            "confidenceScoreThreshold": {"default": self.min_confidence},
            "redactionPolicies": [{"policyKind": self.redaction_policy, "isDefault": True}],
        }
        if self.categories:
            p["piiCategories"] = self.categories
        return p

    @staticmethod
    def _chunk(text: str) -> list[str]:
        """Split into <=5,000-char chunks on whitespace so results can be re-joined exactly."""
        chunks, start = [], 0
        while start < len(text):
            end = min(start + MAX_CHARS_PER_DOC, len(text))
            if end < len(text):
                cut = max(text.rfind(ws, start, end) for ws in (" ", "\n", "\t"))
                if cut > start:
                    end = cut + 1
            chunks.append(text[start:end])
            start = end
        return chunks

    def scan(self, text: str) -> tuple[list[PiiFinding], str]:
        if not text.strip():
            return [], text
        chunks = self._chunk(text)
        findings: list[PiiFinding] = []
        redacted_parts: list[str] = []
        base = 0
        for i in range(0, len(chunks), MAX_DOCS_PER_CALL):
            batch = chunks[i:i + MAX_DOCS_PER_CALL]
            docs = [{"id": str(j), "language": self.language, "text": t} for j, t in enumerate(batch)]
            payload = self.client.analyze(docs, self._parameters())
            result = payload.get("results") if isinstance(payload, dict) else None
            if not isinstance(result, dict) or not isinstance(result.get("documents"), list):
                raise PiiScreeningError("Missing PII document results")
            if result.get("errors"):
                raise PiiScreeningError("PII service reported document errors")
            by_id = {d["id"]: d for d in result["documents"]
                     if isinstance(d, dict) and isinstance(d.get("id"), str)}
            if len(result["documents"]) != len(batch) or len(by_id) != len(batch):
                raise PiiScreeningError("Unexpected PII document results")
            for j, chunk in enumerate(batch):
                doc = by_id.get(str(j))
                if doc is None:
                    raise PiiScreeningError(f"No result returned for chunk {i + j}")
                entities, redacted = doc.get("entities"), doc.get("redactedText")
                if not isinstance(entities, list) or not isinstance(redacted, str):
                    raise PiiScreeningError("Incomplete PII screening result")
                if entities and redacted == chunk:
                    raise PiiScreeningError("PII service did not redact detected entities")
                for e in entities:
                    if (not isinstance(e, dict) or type(e.get("offset")) is not int
                            or type(e.get("length")) is not int or e["offset"] < 0 or e["length"] <= 0
                            or e["offset"] + e["length"] > len(chunk)
                            or e.get("text") != chunk[e["offset"]:e["offset"] + e["length"]]
                            or not isinstance(e.get("category"), str)
                            or not isinstance(e.get("confidenceScore"), (int, float))):
                        raise PiiScreeningError("Invalid PII entity")
                    findings.append(PiiFinding(e["text"], e["category"], e.get("subcategory"),
                                               e["confidenceScore"], base + e["offset"], e["length"]))
                redacted_parts.append(redacted)
                base += len(chunk)
        return findings, "".join(redacted_parts)


class GuardedClaude:
    """Calls Claude in Foundry with PII checks on the prompt and on the answer."""

    def __init__(self, screener: PiiScreener, base_url: str, deployment: str,
                 api_key: str | None = None, input_mode: str = "block",
                 output_mode: str = "redact", max_tokens: int = 1024, claude=None, tls12: bool = False):
        for m in (input_mode, output_mode):
            if m not in ("block", "redact"):
                raise ValueError("modes must be 'block' or 'redact'")
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
        self.input_mode = input_mode
        self.output_mode = output_mode
        self.max_tokens = max_tokens

    # ---------- step 1: prompt ----------
    def check_prompt(self, prompt: str) -> ScreenResult:
        findings, redacted = self.screener.scan(prompt)
        if not findings:
            return ScreenResult("input", "allow", prompt, prompt)
        if self.input_mode == "block":
            return ScreenResult("input", "block", prompt, None, findings)
        return ScreenResult("input", "redact", prompt, redacted, findings)

    # ---------- step 3: output ----------
    def check_output(self, answer: str) -> ScreenResult:
        findings, _ = self.screener.scan(answer)
        # Ignore placeholders from the redacted prompt that Claude echoed back.
        findings = [f for f in findings if not PLACEHOLDER_RE.match(f.text.strip())]
        if not findings:
            return ScreenResult("output", "allow", answer, answer)
        if self.output_mode == "block":
            return ScreenResult("output", "block", answer, None, findings)
        # Redact with our own label so it can't be confused with prompt placeholders.
        safe = answer
        for f in sorted(findings, key=lambda x: x.offset, reverse=True):
            safe = safe[:f.offset] + f"[REDACTED:{f.category}]" + safe[f.offset + f.length:]
        return ScreenResult("output", "redact", answer, safe, findings)

    # ---------- end to end ----------
    def ask(self, prompt: str) -> GuardedResponse:
        # 1. Prompt check
        try:
            p = self.check_prompt(prompt)
        except PiiScreeningError as e:
            log.error("Prompt screening failed, blocking: %s", e)
            p = ScreenResult("input", "block", prompt, None)
            return GuardedResponse(p, None, "Your request could not be screened for personal data, so it was not sent.")
        self._audit(p)
        if p.decision == "block":
            return GuardedResponse(p, None, "Your prompt was not sent because it contains personal data ("
                                   + ", ".join(p.categories) + "). Please remove it and try again.")

        # 2. Claude
        kwargs = dict(model=self.deployment, max_tokens=self.max_tokens,
                      messages=[{"role": "user", "content": p.safe_text}])
        if p.decision == "redact":
            kwargs["system"] = ("Some personal data in the user's message was replaced by placeholders such as "
                                "[PERSON-1] or [EMAIL-2]. Treat them as the real values, keep them as written, "
                                "and never guess or invent personal data.")
        resp = self.claude.messages.create(**kwargs)
        answer = "".join(b.text for b in resp.content if b.type == "text")

        # 3. Output check
        try:
            o = self.check_output(answer)
        except PiiScreeningError as e:
            log.error("Output screening failed, withholding answer: %s", e)
            o = ScreenResult("output", "block", answer, None)
            return GuardedResponse(p, o, "The answer could not be screened for personal data, so it was withheld.")
        self._audit(o)
        if o.decision == "block":
            return GuardedResponse(p, o, "The answer was withheld because it contained personal data ("
                                   + ", ".join(o.categories) + ").")
        return GuardedResponse(p, o, o.safe_text)

    @staticmethod
    def _audit(r: ScreenResult) -> None:
        # Categories and counts only, never the PII values.
        log.info("PII %s decision=%s categories=%s count=%d", r.direction, r.decision, r.categories, len(r.findings))


def build_from_env() -> GuardedClaude:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().with_name(".env"), override=False)
    missing = [n for n in ("LANGUAGE_ENDPOINT", "FOUNDRY_BASE_URL", "CLAUDE_DEPLOYMENT")
               if not os.getenv(n, "").strip()]
    if missing:
        raise ValueError("Missing required 2b settings: " + ", ".join(missing))
    max_tls = os.getenv("TLS_MAX_VERSION", "").strip()
    if max_tls not in ("", "1.2"):
        raise ValueError("TLS_MAX_VERSION supports only 1.2")
    tls12 = max_tls == "1.2"
    categories = [c.strip() for c in os.getenv("PII_CATEGORIES", "").split(",") if c.strip()] or None
    screener = PiiScreener(
        LanguagePiiClient(os.environ["LANGUAGE_ENDPOINT"], os.getenv("LANGUAGE_KEY") or None,
                          os.getenv("PII_API_VERSION") or "2025-11-15-preview", tls12=tls12),
        redaction_policy=os.getenv("PII_POLICY") or "entityMask",
        language=os.getenv("PII_LANGUAGE") or "en",
        min_confidence=float(os.getenv("PII_MIN_CONFIDENCE") or "0.8"),
        categories=categories,
    )
    return GuardedClaude(screener, os.environ["FOUNDRY_BASE_URL"], os.environ["CLAUDE_DEPLOYMENT"],
                         api_key=os.getenv("FOUNDRY_API_KEY") or None,
                         input_mode=(os.getenv("INPUT_PII_MODE") or "block").lower(),
                         output_mode=(os.getenv("OUTPUT_PII_MODE") or "redact").lower(), tls12=tls12)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    guard = build_from_env()
    print(f"Input mode: {guard.input_mode} | Output mode: {guard.output_mode}. Type 'exit' to quit.\n")
    while True:
        prompt = input("You: ").strip()
        if prompt.lower() in ("exit", "quit"):
            break
        if not prompt:
            continue
        r = guard.ask(prompt)
        print(f"  [prompt] {r.prompt_check.decision} {r.prompt_check.categories}")
        if r.prompt_check.decision == "redact":
            print(f"  [sent to Claude] {r.prompt_check.safe_text}")
        if r.output_check:
            print(f"  [output] {r.output_check.decision} {r.output_check.categories}")
        print(f"Claude: {r.answer}\n")
