"""Security/correctness regressions for the research-derived improvements."""
import asyncio
import hashlib
import importlib.util
import json
import os
import unittest
from unittest.mock import patch

import test_worker_efficiency as efficiency
SOURCE = efficiency.SOURCE


class ResearchImprovements(unittest.TestCase):
    def setUp(self):
        self.fixture = efficiency.WorkerEfficiency()
        self.fixture.setUp()
        self.m = self.fixture.m
        self.repo = self.fixture.repo
        self.root = self.fixture.root
        self.git = self.fixture.git

    def tearDown(self):
        self.fixture.tearDown()

    def load_policy(self, profile='all', readonly='0'):
        with patch.dict(os.environ, {'MOORY_ROOT': str(self.root), 'MOORY_TOOL_PROFILE': profile, 'MOORY_READ_ONLY': readonly}):
            spec = importlib.util.spec_from_file_location('moory_policy_test', SOURCE)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        return module

    def tool_names(self, module=None):
        return {tool.name for tool in asyncio.run((module or self.m).mcp.list_tools())}

    def call(self, name, arguments=None, module=None):
        return asyncio.run((module or self.m).mcp.call_tool(name, arguments or {}))

    def add_text(self, name, text):
        (self.repo / name).write_bytes(text.encode('utf-8'))
        self.git('add', name)

    def configure_logs(self):
        self.auth = 'synthetic-auth-A'
        self.info = {'status': 'completed', 'run_attempt': 1, 'updated_at': 'revision-1', 'head_sha': 'a' * 40}
        self.log_counts = {'auth_checks': 0, 'downloads': 0}
        self.revoked = False
        token = 'ghp_' + 'A' * 24
        self.raw_logs = self.fixture.fake_archive('line one\nAuthorization: Bearer ' + token + '\nline three\n')
        self.m.github_installation_token = lambda: (self.auth, {})
        def http(path, **kwargs):
            if path.endswith('/logs'):
                self.log_counts['downloads'] += 1
                return 200, self.raw_logs, {}
            self.log_counts['auth_checks'] += 1
            if self.revoked:
                raise RuntimeError('GitHub API HTTP 403: access revoked')
            return 200, json.dumps(self.info).encode(), {}
        self.m._github_http = http
        return token

    def test_search_masks_whole_multiline_source_before_snippets(self):
        secret = "private-material-that-must-not-leak"
        source = "-----BEGIN " + "PRIVATE KEY-----\n" + secret + "\n-----END " + "PRIVATE KEY-----\n"
        self.add_text("fixture.txt", source)
        self.git("commit", "-m", "synthetic multiline fixture")
        for ref in ("", "HEAD"):
            result = self.m.search_tracked_code("demo", "material", ref=ref)
            self.assertTrue(result["ok"])
            self.assertNotIn(secret, json.dumps(result))
            self.assertTrue(result["redacted"])
        for detail in ("summary", "evidence", "full"):
            result = self.m.worker_context("demo", operation="search", query="material", detail=detail)
            self.assertNotIn(secret, json.dumps(result))
            self.assertTrue(result["matches"][0]["redacted"])

    def test_inventory_cache_changes_on_staged_addition_and_deletion(self):
        first = self.m.worker_context('demo')
        self.add_text('new.py', 'value = 3\n')
        second = self.m.worker_context('demo')
        self.assertEqual(first['cache']['head_sha'], second['cache']['head_sha'])
        self.assertNotEqual(first['cache']['inventory_sha256'], second['cache']['inventory_sha256'])
        self.assertEqual(second['file_count'], first['file_count'] + 1)
        self.assertFalse(second['cache']['hit'])
        again = self.m.worker_context('demo')
        self.assertTrue(again['cache']['hit'])
        self.git('rm', 'sample.py')
        deleted = self.m.worker_context('demo')
        self.assertEqual(deleted['file_count'], first['file_count'])
        self.assertFalse(deleted['cache']['hit'])

    def test_incomplete_inventory_and_status_fail_closed(self):
        original = self.m.run_git
        def git(project, args, **kwargs):
            result = original(project, args, **kwargs)
            if args == ['ls-files', '-z']:
                result['truncated'] = True
            return result
        self.m.run_git = git
        self.assertFalse(self.m.worker_context('demo')['ok'])
        self.assertEqual(self.m.CONTEXT_CACHE, {})
        def fail_status(project, args, **kwargs):
            if args == ['status', '--porcelain']:
                return {'ok': False, 'output': '', 'error': 'status unavailable'}
            return original(project, args, **kwargs)
        self.m.run_git = fail_status
        result = self.m.worker_context('demo')
        self.assertFalse(result['ok'])
        self.assertFalse(result['clean'])

    def test_mask_before_pagination_preserves_original_identity_and_positions(self):
        token = 'ghp_' + 'A' * 24
        password = 'synthetic-password-value'
        text = 'سلام\r\ncredential = ' + repr(token) + '\r\npassword = ' + repr(password) + '\r\n'
        self.add_text('example.txt', text)
        first = self.m.read_tracked_file('demo', 'example.txt')
        self.assertTrue(first['redacted'])
        self.assertNotIn(token, first['content'])
        self.assertNotIn(password, first['content'])
        self.assertEqual(first['sha256'], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(len(first['content']), len(text))
        self.assertEqual(first['content'].count('\r\n'), text.count('\r\n'))
        cursor = {}
        chunks = []
        for _ in range(100):
            page = self.m.read_tracked_file('demo', 'example.txt', maximum_chars=7, **cursor)
            self.assertTrue(page['ok'])
            chunks.append(page['content'])
            if not page['next_cursor']:
                break
            cursor = page['next_cursor']
        self.assertEqual(''.join(chunks), first['content'])
        self.git('commit', '-qm', 'synthetic credential fixture')
        historical = self.m.read_tracked_file('demo', 'example.txt', ref='main')
        self.assertEqual(historical['content'], first['content'])
        self.assertEqual(historical['sha256'], first['sha256'])

    def test_multiline_and_generic_assignment_redaction(self):
        header = '-----BEGIN ' + 'PRIVATE KEY-----'
        footer = '-----END ' + 'PRIVATE KEY-----'
        text = header + '\r\nprivate-material\r\n' + footer + '\napi_key="synthetic-api-secret-value"\npassword="short"\n'
        self.add_text('normal.txt', text)
        r = self.m.read_tracked_file('demo', 'normal.txt')
        self.assertNotIn('private-material', r['content'])
        self.assertNotIn('synthetic-api-secret-value', r['content'])
        self.assertNotIn('short', r['content'])
        self.assertTrue(r['redacted'])
        self.assertEqual(len(text), len(r['content']))

    def test_outbound_nested_payloads_and_search_are_masked(self):
        token = 'ghp_' + 'B' * 24
        def nested_output() -> dict:
            return {'nested': [token], 'public': 'unchanged', 'password': 'short', 'token': 'short-token'}
        self.m.mcp.tool()(nested_output)
        r = self.call('nested_output')
        self.assertNotIn(token, r.model_dump_json())
        self.assertEqual(json.loads(r.content[0].text)['public'], 'unchanged')
        self.assertEqual(json.loads(r.content[0].text)['password'], '*****')
        self.assertNotIn('short-token', r.model_dump_json())
        self.assertGreater(len(r.content), 1)
        self.add_text('example.py', 'credential = ' + repr(token) + '\n')
        for name, args in [('search_tracked_code', {'project': 'demo', 'text': 'credential'}),
                           ('worker_context', {'project': 'demo', 'operation': 'search', 'query': 'credential', 'detail': 'evidence'})]:
            result = self.call(name, args)
            self.assertNotIn(token, result.model_dump_json())
            self.assertIn('*', result.content[0].text)

    def test_typed_structured_output_is_sanitized_too(self):
        from pydantic import BaseModel
        class Model(BaseModel):
            text: str
        token = 'ghp_' + 'C' * 24
        def typed_secret() -> Model:
            return Model(text=token)
        self.m.mcp.tool()(typed_secret)
        result = self.call('typed_secret')
        self.assertIsNotNone(result.structured_content)
        self.assertNotIn(token, result.model_dump_json())
        self.assertEqual(result.structured_content, json.loads(result.content[0].text))

    def test_secret_output_keys_block_without_collisions_and_audit_is_masked(self):
        token = 'ghp_' + 'D' * 24
        def keyed_output() -> dict:
            return {token: 'value'}
        self.m.mcp.tool()(keyed_output)
        result = self.call('keyed_output')
        self.assertTrue(result.is_error)
        self.assertNotIn(token, result.model_dump_json())
        self.assertTrue(self.m.audit('probe', 'demo', False, 'Authorization: Bearer ' + token))
        self.assertNotIn(token, (self.root / 'logs/audit.jsonl').read_text())

    def test_profiles_filter_real_registration_and_readonly_wins(self):
        all_names = self.tool_names()
        core = self.load_policy('core')
        core_names = self.tool_names(core)
        self.assertLess(len(core_names), len(all_names))
        self.assertIn('apply_change_set', core_names)
        self.assertNotIn('github_upsert_collaborator', core_names)
        for profile in ('all', 'core', 'github', 'research'):
            module = self.load_policy(profile, '1')
            names = self.tool_names(module)
            self.assertIn('github_health', names)
            self.assertIn('server_diagnostics', names)
            self.assertNotIn('apply_change_set', names)
            self.assertNotIn('github_merge_pull_request', names)
            self.assertTrue(all(module._is_read_tool(name) for name in names))
            denied = self.call('apply_change_set', {'project': 'demo', 'patch_text': 'not a patch'}, module)
            self.assertTrue(denied.is_error)
        research = self.load_policy('research')
        self.assertTrue(all(research._is_read_tool(name) for name in self.tool_names(research)))
        with self.assertRaises(ValueError):
            self.load_policy('invalid-profile')
        with self.assertRaises(ValueError):
            self.load_policy('all', 'sometimes')

    def test_annotation_hints_match_effective_registration(self):
        tools = {tool.name: tool for tool in asyncio.run(self.m.mcp.list_tools())}
        self.assertTrue(tools['read_tracked_files'].annotations.read_only_hint)
        self.assertFalse(tools['apply_change_set'].annotations.read_only_hint)
        self.assertTrue(tools['apply_change_set'].annotations.destructive_hint)
        self.assertTrue(tools['code_outline'].annotations.read_only_hint)

    def test_log_snapshot_cache_reuses_redacted_content_and_reauthorizes(self):
        token = self.configure_logs()
        first = self.m.github_get_actions_log('demo', 1, start_offset=0, maximum_chars=8)
        self.assertFalse(first['cache']['hit'])
        second = self.m.github_get_actions_log('demo', 1, maximum_chars=8, **first['next_cursor'])
        self.assertTrue(second['cache']['hit'])
        self.assertEqual(self.log_counts, {'auth_checks': 2, 'downloads': 1})
        self.assertNotIn(token, repr(self.m.LOG_SNAPSHOT_CACHE))
        self.revoked = True
        denied = self.m.github_get_actions_log('demo', 1, start_offset=0)
        self.assertFalse(denied['ok'])
        self.assertEqual(self.log_counts['downloads'], 1)

    def test_log_cache_is_partitioned_by_identity_attempt_and_filter(self):
        self.configure_logs()
        self.m._actions_log_snapshot('demo', 1)
        self.auth = 'synthetic-auth-B'
        self.m._actions_log_snapshot('demo', 1)
        self.info['run_attempt'] = 2
        self.m._actions_log_snapshot('demo', 1)
        self.m._actions_log_snapshot('demo', 1, 'line three')
        self.assertEqual(self.log_counts['downloads'], 4)

    def test_log_cache_expiry_running_runs_and_memory_bounds(self):
        self.configure_logs()
        self.m._actions_log_snapshot('demo', 1)
        for item in self.m.LOG_SNAPSHOT_CACHE.values():
            item['expires'] = 0
        self.m._actions_log_snapshot('demo', 1)
        self.assertEqual(self.log_counts['downloads'], 2)
        self.info['status'] = 'in_progress'
        self.m._actions_log_snapshot('demo', 1)
        self.m._actions_log_snapshot('demo', 1)
        self.assertEqual(self.log_counts['downloads'], 4)
        self.info['status'] = 'completed'
        for run in range(2, 9):
            self.m._actions_log_snapshot('demo', run)
        self.assertLessEqual(len(self.m.LOG_SNAPSHOT_CACHE), self.m.LOG_CACHE_MAX_ENTRIES)
        self.assertLessEqual(sum(v['bytes'] for v in self.m.LOG_SNAPSHOT_CACHE.values()), self.m.LOG_CACHE_MAX_BYTES)
        self.m.LOG_SNAPSHOT_CACHE.clear()
        self.m.LOG_CACHE_ENTRY_MAX_BYTES = 1
        self.m._actions_log_snapshot('demo', 99)
        self.assertEqual(len(self.m.LOG_SNAPSHOT_CACHE), 0)

    def test_outline_is_readonly_paginated_and_does_not_expose_defaults(self):
        token = 'ghp_' + 'E' * 24
        code = 'raise RuntimeError("must not execute")\nclass Service:\n    async def fetch(self, key=' + repr(token) + ', *args, **kwargs):\n        def nested():\n            return 1\n        return nested()\n'
        self.add_text('outline.py', code)
        first = self.m.code_outline('demo', 'outline.py', limit=1)
        self.assertTrue(first['ok'])
        self.assertTrue(first['truncated'])
        self.assertIn('not edit evidence', first['representation'])
        second = self.m.code_outline('demo', 'outline.py', limit=10, **first['next_cursor'])
        self.assertEqual([s['qualified_name'] for s in second['symbols']], ['Service.fetch', 'Service.fetch.nested'])
        self.assertEqual(second['symbols'][0]['vararg'], 'args')
        self.assertEqual(second['symbols'][0]['kwarg'], 'kwargs')
        self.assertNotIn(token, json.dumps(first) + json.dumps(second))
        self.assertFalse(self.m.code_outline('demo', 'outline.py', expected_sha256='0' * 64)['ok'])
        self.assertFalse(self.m.code_outline('demo', 'unicode.txt')['ok'])
        self.add_text('broken.py', 'def broken(\n')
        self.assertFalse(self.m.code_outline('demo', 'broken.py')['ok'])

    def test_diagnostics_are_bounded_aggregate_and_schema_identity_is_stable(self):
        self.call('read_tracked_file', {'project': 'demo', 'path': 'sample.py'})
        first = asyncio.run(self.m.server_diagnostics())
        second = asyncio.run(self.m.server_diagnostics())
        self.assertEqual(first['schema_sha256'], second['schema_sha256'])
        self.assertEqual(len(first['source_sha256']), 64)
        self.assertIn('read_tracked_file', first['tool_metrics'])
        self.assertNotIn('arguments', json.dumps(first))
        readonly = self.load_policy('all', '1')
        alternate = asyncio.run(readonly.server_diagnostics())
        self.assertNotEqual(first['schema_sha256'], alternate['schema_sha256'])
        self.assertLessEqual(len(first['tool_metrics']), 256)

    def test_real_http_readonly_profile_and_redacted_read(self):
        import socket
        import subprocess
        import sys
        import time
        import urllib.error
        import urllib.request
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
        token = 'ghp_' + 'F' * 24
        self.add_text('secret-example.txt', 'credential = ' + repr(token) + '\n')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        env = {**os.environ, 'MOORY_ROOT': str(self.root), 'MOORY_PORT': str(port), 'MOORY_TOOL_PROFILE': 'core', 'MOORY_READ_ONLY': '1'}
        process = subprocess.Popen([sys.executable, str(SOURCE)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            ready = False
            for _ in range(100):
                if process.poll() is not None:
                    self.fail('HTTP server exited before startup')
                try:
                    urllib.request.urlopen(f'http://127.0.0.1:{port}/mcp', timeout=0.2).close()
                    ready = True
                except urllib.error.HTTPError:
                    ready = True
                except (OSError, urllib.error.URLError):
                    time.sleep(0.1)
                if ready:
                    break
            self.assertTrue(ready)
            async def check():
                async with streamable_http_client(f'http://127.0.0.1:{port}/mcp') as streams:
                    async with ClientSession(streams[0], streams[1]) as client:
                        await client.initialize()
                        tools = await client.list_tools()
                        names = {tool.name for tool in tools.tools}
                        self.assertIn('code_outline', names)
                        self.assertNotIn('apply_change_set', names)
                        denied = await client.call_tool('apply_unified_patch', {'project': 'demo', 'patch_text': 'not a patch', 'check_only': False})
                        self.assertTrue(denied.is_error)
                        self.assertIn('disabled', denied.content[0].text.lower())
                        response = await client.call_tool('read_tracked_file', {'project': 'demo', 'path': 'secret-example.txt'})
                        self.assertFalse(response.is_error)
                        self.assertNotIn(token, response.model_dump_json())
                        self.assertTrue(json.loads(response.content[0].text)['redacted'])
            asyncio.run(asyncio.wait_for(check(), timeout=20))
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def test_http_metrics_never_record_auth_or_payload(self):
        token = 'synthetic-private-auth'
        self.m._github_http_impl = lambda *a, **k: (200, b'abc', {})
        self.m._github_http('/repos/example/demo', token=token)
        stats = asyncio.run(self.m.server_diagnostics())
        self.assertEqual(stats['github_http_metrics']['calls'], 1)
        self.assertEqual(stats['github_http_metrics']['response_bytes'], 3)
        self.assertNotIn(token, json.dumps(stats))
        self.assertNotIn('/repos/example/demo', json.dumps(stats))


if __name__ == '__main__':
    unittest.main()
