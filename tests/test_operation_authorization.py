"""Authorization UX regressions: no repeated human phrase; no guard removal."""
import ast
import asyncio
import unittest
from unittest.mock import patch

import test_worker_efficiency as efficiency


class OperationAuthorization(unittest.TestCase):
    def setUp(self):
        self.fixture = efficiency.WorkerEfficiency()
        self.fixture.setUp()
        self.m = self.fixture.m

    def tearDown(self):
        self.fixture.tearDown()

    def test_served_guidance_does_not_demand_repeated_user_phrase(self):
        guidance = self.m.OPERATION_AUTHORIZATION_GUIDANCE
        self.assertIn("already explicitly requested", guidance)
        self.assertIn("Do not require the user to repeat", guidance)
        self.assertIn("irreversible consequence is unclear", guidance)
        self.assertIn("does not authorize unrelated actions", guidance)
        self.assertEqual(self.m.moory_capabilities()["operation_authorization"], guidance)
        tools = asyncio.run(self.m.mcp.list_tools())
        merge = next(tool for tool in tools if tool.name == "github_merge_pull_request")
        self.assertIn("agent supplies", merge.description)
        self.assertIn("not the user", merge.description)

    def test_every_existing_marker_guard_stays_present(self):
        source = efficiency.SOURCE.read_text()
        tree = ast.parse(source)
        guarded = {}
        for func in tree.body:
            if isinstance(func, ast.FunctionDef) and any(arg.arg == "confirmation" for arg in func.args.args):
                checks = [node for node in ast.walk(func) if isinstance(node, ast.If) and any(isinstance(part, ast.Name) and part.id == "confirmation" for part in ast.walk(node.test))]
                self.assertTrue(checks, func.name)
                guarded[func.name] = len(checks)
        self.assertEqual(len(guarded), 42)

    def test_internal_marker_reaches_write_only_for_authorized_call(self):
        m = self.m
        with patch.object(m, "github_json", return_value={"state": "open", "draft": False, "mergeable": True}), patch.object(m, "github_write_json", return_value={"status": 200, "data": {"merged": True, "sha": "a" * 40}}) as write:
            blocked = m.github_merge_pull_request("demo", 6)
            self.assertFalse(blocked["ok"])
            write.assert_not_called()
            # The agent fills the marker from the already-authorized operation.
            result = m.github_merge_pull_request("demo", 6, confirmation="MERGE PR #6")
            self.assertTrue(result["ok"])
            write.assert_called_once()

    def test_valid_marker_cannot_override_draft_check(self):
        m = self.m
        with patch.object(m, "github_json", return_value={"state": "open", "draft": True}), patch.object(m, "github_write_json") as write:
            result = m.github_merge_pull_request("demo", 6, confirmation="MERGE PR #6")
            self.assertFalse(result["ok"])
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
