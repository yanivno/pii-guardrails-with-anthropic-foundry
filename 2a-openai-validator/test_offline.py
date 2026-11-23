import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

import httpx
from openai import APIStatusError, APITimeoutError
from openai.types.responses import Response

from claude_validator import GuardedClaude, build_from_env


def verdict(content="ALLOW", status="completed", **metadata):
    message = dict(id="msg", type="message", status="completed", role="assistant",
                   content=[dict(type="output_text", text=content, annotations=[])])
    return Response(id="test", model="validator", created_at=0, object="response", status=status,
                    output=[message], parallel_tool_calls=False, tool_choice="none", tools=[], **metadata)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.validator, self.claude = Mock(), Mock()
        self.guard = GuardedClaude(self.validator, "validator", self.claude, "claude")
        self.review = self.validator.responses.create
        self.claude.messages.create.return_value.content = [SimpleNamespace(type="text", text="draft")]

    def test_checks_exact_prompt_and_answer(self):
        self.review.side_effect = [verdict(), verdict()]
        self.assertEqual(self.guard.ask("hello"), "draft")
        self.assertEqual([c.kwargs["input"] for c in self.review.call_args_list],
                         ["hello", "draft"])

    def test_verbose_logs_explain_withholding_without_recording_content(self):
        self.review.side_effect = [verdict(), verdict("private reviewer reply")]
        with self.assertLogs("claude-validator", level="DEBUG") as logs:
            self.guard.ask("private user text")
        trace = "\n".join(logs.output)
        self.assertIn("Prompt approved", trace)
        self.assertIn("no explicit ALLOW verdict", trace)
        self.assertIn("Answer withheld", trace)
        for private in ("private user text", "private reviewer reply", "draft"):
            self.assertNotIn(private, trace)

    def test_no_claude_call_without_approval(self):
        for response in [verdict("DENY"), verdict("ALLOW with exceptions"),
                         verdict(status="incomplete"), verdict(status="failed"),
                         verdict(content_filters=[{"content_filter_results": {"error": {}}}]),
                         APITimeoutError(request=httpx.Request("POST", "https://example.invalid"))]:
            with self.subTest(response=type(response).__name__), \
                    self.assertLogs("claude-validator", level="DEBUG") as logs:
                self.review.side_effect = [response]
                self.assertIn("not sent", self.guard.ask("hello"))
                self.claude.messages.create.assert_not_called()
                self.assertIn("Prompt blocked; Claude not called", "\n".join(logs.output))

    def test_no_release_without_output_approval(self):
        self.review.side_effect = [verdict(), verdict("DENY")]
        self.assertEqual(self.guard.ask("hello"), "Answer not approved; it was withheld.")

    def test_api_failure_logs_diagnostics_not_response_body(self):
        response = httpx.Response(404, request=httpx.Request("POST", "https://example.invalid"),
                                  headers={"apim-request-id": "trace-123"})
        self.review.side_effect = APIStatusError("private error message", response=response,
                                                 body={"code": "DeploymentNotFound", "message": "private body"})
        with self.assertLogs("claude-validator", level="WARNING") as logs:
            self.assertIn("not sent", self.guard.ask("private prompt"))
        warning = "\n".join(logs.output)
        for detail in ("APIStatusError", "HTTP 404", "DeploymentNotFound", "trace-123"):
            self.assertIn(detail, warning)
        self.assertNotIn("private", warning)
        self.claude.messages.create.assert_not_called()

    def test_allow_text_cannot_override_refusal_or_ambiguous_verdict(self):
        refused = verdict()
        from openai.types.responses import ResponseOutputRefusal
        refused.output[0].content.append(ResponseOutputRefusal(type="refusal", refusal="Cannot review"))
        empty = verdict()
        empty.output.clear()
        multiple = verdict()
        multiple.output.extend(verdict("DENY").output)
        for label, response in [("refusal", refused), ("no choices", empty),
                                ("conflicting choices", multiple)]:
            with self.subTest(label=label):
                self.review.return_value = response
                self.assertIn("not sent", self.guard.ask("hello"))
                self.claude.messages.create.assert_not_called()

    def test_nested_filter_flags_override_allow(self):
        blocked = {"violence": {"filtered": True}}
        prompt_flag = verdict(content_filters=[{"source_type": "prompt", "content_filter_results": blocked}])
        answer_flag = verdict(content_filters=[{"source_type": "completion", "blocked": True}])
        self.review.side_effect = [prompt_flag, verdict(), answer_flag]
        self.assertIn("not sent", self.guard.ask("first"))
        self.claude.messages.create.assert_not_called()
        self.assertEqual(self.guard.ask("second"), "Answer not approved; it was withheld.")
        self.claude.messages.create.assert_called_once()

    def test_timeout_during_output_review_withholds_entire_draft(self):
        timeout = APITimeoutError(request=httpx.Request("POST", "https://example.invalid"))
        self.review.side_effect = [verdict(), timeout]
        with self.assertLogs("claude-validator", level="WARNING"):
            self.assertEqual(self.guard.ask("hello"), "Answer not approved; it was withheld.")
        self.claude.messages.create.assert_called_once()

    def test_only_reviewed_text_blocks_are_released(self):
        self.claude.messages.create.return_value.content = [
            SimpleNamespace(type="text", text="First. "),
            SimpleNamespace(type="thinking", thinking="internal"),
            SimpleNamespace(type="text", text="Second."),
        ]
        clean = verdict(content_filters=[{"content_filter_results": {
            "violence": {"filtered": False}}}])
        self.review.side_effect = [clean, clean]
        answer = self.guard.ask("hello")
        self.assertEqual(answer, "First. Second.")
        self.assertEqual(self.review.call_args.kwargs["input"], answer)


class ConfigTests(unittest.TestCase):
    def test_sibling_dotenv_with_exported_override(self):
        with TemporaryDirectory() as folder, patch.dict(os.environ, {"CLAUDE_DEPLOYMENT": "exported"}, clear=True):
            (Path(folder) / ".env").write_text(
                "VALIDATOR_BASE_URL=https://example.invalid/openai/v1/\nVALIDATOR_DEPLOYMENT=review\n"
                "FOUNDRY_BASE_URL=https://example.invalid/anthropic\nCLAUDE_DEPLOYMENT=file\n"
                "VALIDATOR_API_KEY=test\nFOUNDRY_API_KEY=test\n"
            )
            with patch("claude_validator.__file__", str(Path(folder) / "claude_validator.py")):
                guard = build_from_env()
            self.assertEqual(guard.validator_deployment, "review")
            self.assertEqual(guard.claude_deployment, "exported")

    def test_missing_configuration_reports_setting(self):
        with TemporaryDirectory() as folder, patch.dict(os.environ, {}, clear=True):
            with patch("claude_validator.__file__", str(Path(folder) / "claude_validator.py")):
                with self.assertRaisesRegex(ValueError, "VALIDATOR_BASE_URL"):
                    build_from_env()

    def test_tls_cap_keeps_certificate_verification(self):
        import ssl
        from claude_validator import http_client
        self.assertIsNone(http_client(""))
        with http_client("1.2") as client:
            context = client._transport._pool._ssl_context
            self.assertEqual(context.maximum_version, ssl.TLSVersion.TLSv1_2)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        with self.assertRaises(ValueError):
            http_client("1.0")


if __name__ == "__main__":
    unittest.main()
