import importlib.util
import json
import os
import re
import tempfile
from pathlib import Path

repository_root = Path(__file__).resolve().parents[1]
server_path = repository_root / "src/moory/server.py"

with tempfile.TemporaryDirectory() as temporary:
    runtime_root = Path(temporary)
    repo = runtime_root / "repos/demo"
    config = runtime_root / "config"
    logs = runtime_root / "logs"
    repo.mkdir(parents=True)
    config.mkdir()
    logs.mkdir()
    (config / "projects.json").write_text(json.dumps({"demo": {"repo": "example/demo", "branch": "main", "path": str(repo)}}), encoding="utf-8")
    os.environ["MOORY_ROOT"] = str(runtime_root)
    os.environ["MOORY_PORT"] = "18787"
    spec = importlib.util.spec_from_file_location("moory_runtime_test", server_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.PROJECTS = {"demo": {"repo": "example/demo", "branch": "main", "path": repo}}

    safe = repo / "README.md"
    sensitive = repo / ".env"
    safe.write_text("safe content\n", encoding="utf-8")
    sensitive.write_text("not-a-real-secret\n", encoding="utf-8")
    link = repo / "linked-config"
    link.symlink_to(sensitive)

    assert module.safe_search_candidate("demo", "README.md") == safe
    assert module.safe_search_candidate("demo", ".env") is None
    assert module.safe_search_candidate("demo", "linked-config") is None

    secrets = [
        "AKIA" + "A" * 16,
        "AIza" + "A" * 35,
        "xoxb-" + "A" * 24,
        "sk_live_" + "A" * 24,
        "glpat-" + "A" * 24,
        "pypi-" + "A" * 44,
        "npm_" + "A" * 36,
    ]
    for value in secrets:
        assert re.search(module.SECRET_PATTERN, value), value[:8]

    assert module.audit("runtime_test", "demo", True, "durable")
    audit_text = (logs / "audit.jsonl").read_text(encoding="utf-8")
    assert "runtime_test" in audit_text

    secret = "ghp_" + "A" * 24
    redacted = module.redact_github_text("Authorization: Bearer " + secret)
    assert secret not in redacted

    draft = {
        "id": 1,
        "tag_name": "v1.1.0",
        "name": "RC",
        "draft": True,
        "prerelease": True,
        "target_commitish": "old-head",
        "assets": [],
    }
    captured = {}

    def fake_github_json(project, path, query=None):
        if path.startswith("/releases/tags/"):
            raise RuntimeError("draft tag endpoint unavailable")
        if path == "/releases":
            return [draft]
        if path == "/releases/1":
            return draft
        raise AssertionError(path)

    def fake_github_write_json(project, path, method, body, audit_action):
        captured["body"] = body
        return {"status": 200, "data": {**draft, **body}}

    module.github_json = fake_github_json
    module.github_write_json = fake_github_write_json
    loaded = module.github_get_release("demo", "v1.1.0")
    assert loaded["ok"] and loaded["release"]["draft"]
    updated = module.github_update_release("demo", 1, target_commitish="new-head")
    assert updated["ok"] and captured["body"]["target_commitish"] == "new-head"

    blocked_deployment = module.github_create_deployment("demo", "main", confirmation="")
    assert not blocked_deployment["ok"] and "DEPLOY main TO production" in blocked_deployment["error"]

    captured.clear()

    def fake_variable_json(project, path, query=None):
        if path == "/actions/variables/TEST_VAR":
            raise RuntimeError("GitHub API HTTP 404: Not Found")
        raise AssertionError(path)

    def fake_variable_write(project, path, method, body, audit_action):
        captured.update({"path": path, "method": method, "body": body, "audit_action": audit_action})
        return {"status": 201, "data": {}}

    module.github_json = fake_variable_json
    module.github_write_json = fake_variable_write
    variable = module.github_upsert_actions_variable(
        "demo", "test_var", "public-value", confirmation="CREATE VARIABLE TEST_VAR IN repository"
    )
    assert variable["ok"] and variable["value_redacted"]
    assert captured["path"] == "/actions/variables" and captured["method"] == "POST"
    assert "public-value" not in json.dumps(variable)

    blocked_workflow = module.github_set_workflow_state("demo", "ci.yml", "disable", confirmation="")
    assert not blocked_workflow["ok"] and "DISABLE WORKFLOW ci.yml" in blocked_workflow["error"]

    bad_check = module.github_create_check_run("demo", "Moory", "short", confirmation="")
    assert not bad_check["ok"] and "40-character" in bad_check["error"]

    blocked_status = module.github_create_commit_status("demo", "a" * 40, "success", confirmation="")
    assert not blocked_status["ok"] and "SET STATUS default success ON" in blocked_status["error"]

    blocked_secret = module.github_update_secret_scanning_alert("demo", 1, "resolved", "false_positive", confirmation="")
    assert not blocked_secret["ok"] and "UPDATE SECRET ALERT 1 TO resolved" in blocked_secret["error"]

    blocked_code = module.github_update_code_scanning_alert("demo", 1, "dismissed", "false positive", confirmation="")
    assert not blocked_code["ok"] and "UPDATE CODE ALERT 1 TO dismissed" in blocked_code["error"]

    blocked_advisory = module.github_create_repository_security_advisory("demo", "Test advisory", "Safe description", "high", "pip", "demo", "< 1.0", confirmation="")
    assert not blocked_advisory["ok"] and "CREATE SECURITY ADVISORY Test advisory" in blocked_advisory["error"]

    blocked_publish = module.github_update_repository_security_advisory("demo", "GHSA-ABCD-EFGH-IJKL", state="published", confirmation="")
    assert not blocked_publish["ok"] and "PUBLISH SECURITY ADVISORY GHSA-ABCD-EFGH-IJKL" in blocked_publish["error"]

    valid_digest = "sha256:" + "a" * 64
    blocked_attestation = module.github_create_attestation("demo", {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {}, "dsseEnvelope": {}}, confirmation="")
    assert not blocked_attestation["ok"] and "CREATE ATTESTATION" in blocked_attestation["error"]

    snapshot = {"version": 0, "job": {}, "sha": "a" * 40, "ref": "refs/heads/main", "detector": {}, "manifests": {}}
    blocked_snapshot = module.github_submit_dependency_snapshot("demo", snapshot, confirmation="")
    assert not blocked_snapshot["ok"] and "SUBMIT DEPENDENCY SNAPSHOT" in blocked_snapshot["error"]

    blocked_storage = module.github_create_artifact_storage_record("demo", "artifact", valid_digest, "https://registry.example.com", confirmation="")
    assert not blocked_storage["ok"] and "STORE ARTIFACT artifact" in blocked_storage["error"]

    blocked_artifact_deploy = module.github_create_artifact_deployment_record("demo", "artifact", valid_digest, "production", "web", confirmation="")
    assert not blocked_artifact_deploy["ok"] and "DEPLOY ARTIFACT artifact TO production" in blocked_artifact_deploy["error"]

    blocked_label = module.github_upsert_label("demo", "priority", "ff0000", confirmation="")
    assert not blocked_label["ok"] and "UPSERT LABEL priority" in blocked_label["error"]

    blocked_milestone = module.github_upsert_milestone("demo", "v2", confirmation="")
    assert not blocked_milestone["ok"] and "UPSERT MILESTONE v2" in blocked_milestone["error"]

    blocked_reviewers = module.github_request_pull_request_reviewers("demo", 1, ["octocat"], confirmation="")
    assert not blocked_reviewers["ok"] and "REQUEST REVIEWERS PR #1" in blocked_reviewers["error"]

    blocked_assignees = module.github_add_issue_assignees("demo", 1, ["octocat"], confirmation="")
    assert not blocked_assignees["ok"] and "ASSIGN ISSUE #1" in blocked_assignees["error"]

    blocked_discussion = module.github_create_discussion("demo", "DIC_test", "Test", "Safe body", confirmation="")
    assert not blocked_discussion["ok"] and "CREATE DISCUSSION Test" in blocked_discussion["error"]

    blocked_comment = module.github_comment_discussion("demo", "D_test", "Safe comment", confirmation="")
    assert not blocked_comment["ok"] and "COMMENT DISCUSSION D_test" in blocked_comment["error"]

    blocked_update_discussion = module.github_update_discussion("demo", "D_test", title="Updated", confirmation="")
    assert not blocked_update_discussion["ok"] and "UPDATE DISCUSSION D_test" in blocked_update_discussion["error"]

    blocked_queue = module.github_set_pull_request_queue_state("demo", 1, "enqueue", confirmation="")
    assert not blocked_queue["ok"] and "ENQUEUE PR #1" in blocked_queue["error"]
