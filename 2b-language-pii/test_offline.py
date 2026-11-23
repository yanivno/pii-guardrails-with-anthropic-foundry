"""Offline test for claude_pii_guard.py: simulates the PII REST API and Claude, no Azure needed.
Run: python test_offline.py"""
import logging, re, types
from unittest import mock
from claude_pii_guard import LanguagePiiClient, PiiScreener, GuardedClaude, PiiScreeningError

PATTERNS = [(r"[\w.]+@[\w.]+\.\w+", "Email"), (r"\d{3}-\d{3}-\d{4}", "PhoneNumber"), (r"John Doe|Jane Roe", "Person")]

def fake_post(url, params=None, headers=None, json=None, timeout=None):
    assert url.endswith("/language/:analyze-text") and params["api-version"]
    assert json["kind"] == "PiiEntityRecognition" and len(json["analysisInput"]["documents"]) <= 5
    # The live API returns 400 unless exactly one redaction policy is the default.
    assert sum(p.get("isDefault") is True for p in json["parameters"]["redactionPolicies"]) == 1
    docs = []
    for d in json["analysisInput"]["documents"]:
        ents, red, n = [], d["text"], {}
        for p, c in PATTERNS:
            for m in re.finditer(p, d["text"]):
                ents.append({"text": m.group(0), "category": c, "offset": m.start(),
                             "length": len(m.group(0)), "confidenceScore": 0.95})
        for e in sorted(ents, key=lambda e: -e["offset"]):
            n[e["category"]] = n.get(e["category"], 0) + 1
            red = red[:e["offset"]] + f"[{e['category'].upper()}_{n[e['category']]}]" + red[e["offset"] + e["length"]:]
        docs.append({"id": d["id"], "redactedText": red, "entities": ents, "warnings": []})
    return types.SimpleNamespace(status_code=200, text="",
        json=lambda: {"kind": "PiiEntityRecognitionResults", "results": {"documents": docs, "errors": []}})

class FakeClaude:
    def __init__(self, reply): self.reply, self.calls, self.messages = reply, [], self
    def create(self, **kw):
        self.calls.append(kw["messages"][-1]["content"])
        return types.SimpleNamespace(content=[types.SimpleNamespace(type="text", text=self.reply)])

def guard(reply, inp="block", out="redact"):
    s = PiiScreener(LanguagePiiClient("https://fake.cognitiveservices.azure.com", api_key="x"))
    return GuardedClaude(s, "", "d", input_mode=inp, output_mode=out, claude=FakeClaude(reply))

logging.basicConfig(level=logging.WARNING)
with mock.patch("requests.post", fake_post):
    g = guard("Q3 revenue grew 12%."); r = g.ask("Summarize Q3")
    assert r.prompt_check.decision == "allow" and r.output_check.decision == "allow"; print("1 clean          :", r.answer)

    g = guard("unused"); r = g.ask("Email John Doe at john@contoso.com")
    assert r.prompt_check.decision == "block" and r.output_check is None and not g.claude.calls; print("2 prompt blocked :", r.answer)

    g = guard("I'll write to [EMAIL_1] for [PERSON_1].", inp="redact"); r = g.ask("Email John Doe at john@contoso.com")
    assert g.claude.calls[0] == "Email [PERSON_1] at [EMAIL_1]" and r.output_check.decision == "allow"
    print("3 placeholders   :", g.claude.calls[0], "->", r.answer)

    g = guard("Contact Jane Roe at jane@fabrikam.com or 054-555-0123."); r = g.ask("Who handles billing?")
    assert r.output_check.decision == "redact" and "jane@fabrikam.com" not in r.answer; print("4 output redact  :", r.answer)

    g = guard("Contact Jane Roe at jane@fabrikam.com.", out="block"); r = g.ask("Who handles billing?")
    assert r.output_check.decision == "block" and "jane" not in r.answer; print("5 output blocked :", r.answer)

    long_reply = "word " * 6000 + "call 054-555-0123"
    g = guard(long_reply); r = g.ask("long")
    assert "054-555-0123" not in r.answer and r.answer.endswith("[REDACTED:PhoneNumber]"); print("6 long output    : redacted across", len(PiiScreener._chunk(long_reply)), "chunks")

def failing_post(*a, **k): return types.SimpleNamespace(status_code=500, text="boom", json=lambda: {})
with mock.patch("requests.post", failing_post):
    g = guard("x"); r = g.ask("hi")
    assert r.prompt_check.decision == "block" and not g.claude.calls; print("7 fail closed    :", r.answer)
for missing in ("entities", "redactedText"):
    def incomplete(*args, **kwargs):
        body = fake_post(*args, **kwargs).json()
        del body["results"]["documents"][0][missing]
        return types.SimpleNamespace(status_code=200, json=lambda: body)
    with mock.patch("requests.post", incomplete):
        g = guard("unused", inp="redact")
        r = g.ask("Email John Doe")
        assert r.prompt_check.decision == "block" and not g.claude.calls

with mock.patch("requests.post", side_effect=[
    types.SimpleNamespace(status_code=200, json=lambda: {"results": {"documents": [
        {"id": "0", "entities": [], "redactedText": "hello"}]}}),
    types.SimpleNamespace(status_code=500),
]):
    r = guard("private answer").ask("hello")
    assert r.output_check.decision == "block" and "private answer" not in r.answer
print("ALL TESTS PASSED")
