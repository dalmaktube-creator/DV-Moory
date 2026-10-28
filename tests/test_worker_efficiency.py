"""Integration regressions with real Git repositories and the pinned MCP SDK."""
import asyncio
import hashlib
import importlib.util
import io
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
import subprocess
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'src/moory/server.py'


class WorkerEfficiency(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repos/demo'
        self.repo.mkdir(parents=True)
        (self.root / 'config').mkdir()
        (self.root / 'logs').mkdir()
        (self.root / 'config/github-auth.env').write_text('# Isolated local test, no credentials\n')
        config = {'demo': {'repo': 'example/demo', 'branch': 'main', 'path': str(self.repo)}}
        (self.root / 'config/projects.json').write_text(json.dumps(config))
        with patch.dict(os.environ, {'MOORY_ROOT': str(self.root)}):
            spec = importlib.util.spec_from_file_location('moory_efficiency_test', SOURCE)
            self.m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.m)
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Test')
        (self.repo / 'sample.py').write_text('value = 1\n')
        (self.repo / 'unicode.txt').write_bytes(('سلام\r\n' + 'x' * 60_000 + '\nlast\n').encode())
        self.git('add', '.')
        self.git('commit', '-qm', 'baseline')

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo), *args], check=True, capture_output=True).stdout.decode()

    def diff(self):
        return self.git('diff', '--no-ext-diff', '--binary')

    def patch_value(self, new='value = 2\n'):
        (self.repo / 'sample.py').write_text(new)
        result = self.diff()
        self.git('restore', '--worktree', '--', 'sample.py')
        return result

    def fake_archive(self, text, extra=None):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('job/log.txt', text)
            for name, value in (extra or {}).items():
                z.writestr(name, value)
        return buf.getvalue()

    def use_archive(self, raw):
        self.m.github_installation_token = lambda: ('not-a-real-credential', {})
        self.m._github_http = lambda *a, **k: (200, raw, {})

    def test_exact_resumable_reads_worktree_and_ref(self):
        expected = (self.repo / 'unicode.txt').read_bytes()
        for ref in ('', 'main'):
            cursor = {}
            chunks = []
            for _ in range(100):
                r = self.m.read_tracked_file('demo', 'unicode.txt', ref=ref, maximum_chars=1000, **cursor)
                self.assertTrue(r['ok'], r)
                self.assertEqual(r['sha256'], hashlib.sha256(expected).hexdigest())
                chunks.append(r['content'])
                if not r['next_cursor']:
                    break
                cursor = r['next_cursor']
            else:
                self.fail('read cursor did not advance')
            self.assertEqual(''.join(chunks).encode(), expected)

    def test_changed_read_identity_fails_closed(self):
        r = self.m.read_tracked_file('demo', 'sample.py', maximum_chars=2)
        (self.repo / 'sample.py').write_text('value = 3\n')
        later = self.m.read_tracked_file('demo', 'sample.py', **r['next_cursor'])
        self.assertFalse(later['ok'])
        self.assertIn('Source changed', later['error'])

    def test_batch_budget_and_sensitive_paths(self):
        r = self.m.read_tracked_files('demo', [{'path': 'sample.py'}, {'path': 'unicode.txt'}], maximum_chars=12)
        self.assertTrue(r['ok'])
        self.assertEqual(sum(len(x['content']) for x in r['results']), 12)
        self.assertTrue(r['truncated'])
        for path in ('.env', '../outside', '.git/config', '/etc/passwd'):
            self.assertFalse(self.m.read_tracked_file('demo', path)['ok'])
        (self.repo / 'link').symlink_to('sample.py')
        self.git('add', 'link')
        self.git('commit', '-qm', 'track link')
        for ref in ('', 'main'):
            self.assertFalse(self.m.read_tracked_file('demo', 'link', ref=ref)['ok'])

    def test_guarded_atomic_edit(self):
        p = self.patch_value()
        before = (self.repo / 'sample.py').read_bytes()
        r = self.m.apply_change_set('demo', p, False, expected_head=self.git('rev-parse', 'HEAD').strip(),
                                    expected_sha256={'sample.py': hashlib.sha256(before).hexdigest()})
        self.assertTrue(r['ok'], r)
        self.assertTrue(r['sha_guarded'])
        self.assertEqual((self.repo / 'sample.py').read_text(), 'value = 2\n')

    def test_stale_head_and_file_rejected_without_writes(self):
        p = self.patch_value()
        for options in ({'expected_head': '0' * 40}, {'expected_sha256': {'sample.py': '0' * 64}}):
            r = self.m.apply_change_set('demo', p, False, **options)
            self.assertFalse(r['ok'])
            self.assertEqual(self.git('status', '--porcelain'), '')

    def test_added_invalid_file_rolls_back_edit_and_addition(self):
        p = self.patch_value() + 'diff --git a/new.py b/new.py\nnew file mode 100644\n--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+def broken(\n'
        r = self.m.apply_change_set('demo', p, False)
        self.assertFalse(r['ok'], r)
        self.assertTrue(r['clean_after_rollback'], r)
        self.assertFalse((self.repo / 'new.py').exists())
        self.assertEqual((self.repo / 'sample.py').read_text(), 'value = 1\n')

    def test_new_file_success(self):
        p = 'diff --git a/new.py b/new.py\nnew file mode 100644\n--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+value = 2\n'
        r = self.m.apply_change_set('demo', p, False)
        self.assertTrue(r['ok'], r)
        self.assertIn('new.py', r['added_paths'])
        self.assertEqual(r['validation']['checks']['syntax']['python'], 2)

    def test_deletion_rollback_and_exception_rollback(self):
        (self.repo / 'sample.py').unlink()
        p = self.diff()
        self.git('restore', '--worktree', '--', 'sample.py')
        self.m.validate_project = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('validator unavailable'))
        r = self.m.apply_change_set('demo', p, False)
        self.assertFalse(r['ok'])
        self.assertTrue(r['clean_after_rollback'])
        self.assertEqual((self.repo / 'sample.py').read_text(), 'value = 1\n')

    def test_transaction_keeps_lock_through_validation_and_rollback(self):
        entered = threading.Event()
        release = threading.Event()
        acquired = threading.Event()
        result = {}
        def validate(*a, **k):
            entered.set()
            self.assertTrue(release.wait(5))
            return {'ok': False, 'error': 'test failure'}
        self.m.validate_project = validate
        p = self.patch_value()
        t = threading.Thread(target=lambda: result.update(self.m.apply_change_set('demo', p, False)))
        t.start()
        self.assertTrue(entered.wait(5))
        def competing_write():
            with self.m.WRITE_LOCK:
                acquired.set()
        other = threading.Thread(target=competing_write)
        other.start()
        try:
            self.assertFalse(acquired.wait(0.1), 'another write entered during validation')
        finally:
            release.set()
            t.join(5)
            other.join(5)
        self.assertFalse(t.is_alive())
        self.assertTrue(acquired.is_set())
        self.assertTrue(result['clean_after_rollback'])

    def test_ci_long_assertion_is_compact_and_fully_resumable(self):
        raw = self.fake_archive('start\nAssertionError: ' + 'x' * 240_000 + '\nfailed tail\n')
        self.use_archive(raw)
        self.m.github_get_workflow_run = lambda *a: {'ok': True, 'workflow_run': {'conclusion': 'failure'}, 'jobs': []}
        r = self.m.inspect_ci_failure('demo', 1, 'evidence')
        self.assertTrue(r['ok'])
        self.assertTrue(r['truncated'])
        self.assertLess(len(json.dumps(r)), 20_000)
        expected = self.m._actions_log_snapshot('demo', 1)['output']
        request = r['full_evidence_request']
        chunks = []
        while True:
            page = self.m.github_get_actions_log(**request, maximum_chars=7000)
            self.assertTrue(page['ok'], page)
            chunks.append(page['output'])
            if not page['next_cursor']:
                break
            request = {'project': 'demo', 'run_id': 1, **page['next_cursor']}
        self.assertEqual(''.join(chunks), expected)

    def test_ci_all_lines_scanned_and_duplicate_groups_disclosed(self):
        self.use_archive(self.fake_archive('failure: first\n' + 'noise\n' * 1000 + 'failure: last\n'))
        self.m.github_get_workflow_run = lambda *a: {'ok': True, 'jobs': []}
        r = self.m.inspect_ci_failure('demo', 1, 'evidence')
        self.assertEqual(r['total_error_groups'], 2)
        self.assertIn('first', r['error_groups'][0]['message'])
        self.assertIn('last', r['error_groups'][1]['message'])

    def test_ci_source_change_redaction_and_archive_limits(self):
        token = 'ghp_' + 'a' * 24
        key = '-----BEGIN ' + 'PRIVATE KEY-----\nprivate material\n-----END ' + 'PRIVATE KEY-----'
        self.use_archive(self.fake_archive('Authorization: Bearer ' + token + '\n' + key))
        r = self.m.github_get_actions_log('demo', 1, start_offset=0)
        self.assertNotIn(token, r['output'])
        self.assertNotIn('private material', r['output'])
        self.use_archive(self.fake_archive('new content'))
        self.assertFalse(self.m.github_get_actions_log('demo', 1, start_offset=0, expected_sha256=r['source_sha256'])['ok'])
        self.use_archive(self.fake_archive('x', {f'{n}.txt': 'x' for n in range(201)}))
        self.assertFalse(self.m.github_get_actions_log('demo', 1)['ok'])

    def test_static_validation_discloses_incomplete_inventory(self):
        original = self.m.run_git
        def git(project, args, **kwargs):
            r = original(project, args, **kwargs)
            if args == ['ls-files']:
                r['truncated'] = True
            return r
        self.m.run_git = git
        r = self.m.validate_project('demo')
        self.assertFalse(r['ok'])
        self.assertFalse(r['complete'])
        self.assertTrue(r['truncated'])

    def test_git_output_truncation_is_explicit(self):
        r = self.m.run_git('demo', ['log', '-1', '--format=%H'], output_limit=3)
        self.assertTrue(r['truncated'])
        self.assertGreater(r['output_characters'], 3)

    def test_streamable_http_sdk_roundtrip(self):
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        env = {**os.environ, 'MOORY_ROOT': str(self.root), 'MOORY_PORT': str(port)}
        process = subprocess.Popen([sys.executable, str(SOURCE)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            ready = False
            for _ in range(100):
                if process.poll() is not None:
                    self.fail('MCP HTTP subprocess exited before startup')
                try:
                    urllib.request.urlopen(f'http://127.0.0.1:{port}/mcp', timeout=0.2).close()
                    ready = True
                except urllib.error.HTTPError:
                    ready = True
                except (OSError, urllib.error.URLError):
                    time.sleep(0.1)
                if ready:
                    break
            self.assertTrue(ready, 'MCP HTTP server did not start')
            async def call():
                async with streamable_http_client(f'http://127.0.0.1:{port}/mcp') as streams:
                    async with ClientSession(streams[0], streams[1]) as client:
                        await client.initialize()
                        result = await client.call_tool('read_tracked_files', {'project': 'demo', 'requests': [{'path': 'sample.py'}]})
                        self.assertFalse(result.is_error)
                        parsed = json.loads(result.content[0].text)
                        self.assertEqual(parsed['results'][0]['content'], 'value = 1\n')
                        if result.structured_content is not None:
                            self.assertEqual(result.structured_content, parsed)
                        self.assertNotIn('\n  ', result.content[0].text)
            asyncio.run(asyncio.wait_for(call(), timeout=20))
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def test_typed_sdk_schema_and_structured_output_survive_compaction(self):
        from mcp.server import MCPServer
        from pydantic import BaseModel
        class EvidenceModel(BaseModel):
            message: str
            values: list[int]
        def typed_evidence() -> EvidenceModel:
            return EvidenceModel(message='سلام', values=[1, 2, 3])
        self.m.mcp.tool()(typed_evidence)
        baseline = asyncio.run(MCPServer.call_tool(self.m.mcp, 'typed_evidence', {}))
        compact = asyncio.run(self.m.mcp.call_tool('typed_evidence', {}))
        self.assertIsNotNone(baseline.structured_content)
        self.assertEqual(compact.structured_content, baseline.structured_content)
        self.assertEqual(json.loads(compact.content[0].text), json.loads(baseline.content[0].text))
        self.assertLess(len(compact.content[0].text.encode()), len(baseline.content[0].text.encode()))
        tools = {tool.name: tool for tool in asyncio.run(self.m.mcp.list_tools())}
        self.assertIsNotNone(tools['typed_evidence'].output_schema)

    def test_real_sdk_compact_serialization_preserves_json_and_schema(self):
        raw = self.m.read_tracked_file('demo', 'sample.py')
        tool = asyncio.run(self.m.mcp.call_tool('read_tracked_file', {'project': 'demo', 'path': 'sample.py'}))
        self.assertEqual(json.loads(tool.content[0].text), raw)
        if tool.structured_content is not None:
            self.assertEqual(tool.structured_content, raw)
        self.assertNotIn('\n  ', tool.content[0].text)
        self.assertFalse(tool.is_error)
        tools = asyncio.run(self.m.mcp.list_tools())
        found = {t.name: t for t in tools}
        self.assertIn('read_tracked_files', found)
        self.assertIn('expected_sha256', found['apply_change_set'].input_schema['properties'])


if __name__ == '__main__':
    unittest.main()
