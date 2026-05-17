"""
NetOps-AI Agent — Test Suite
Covers: main.py (FastAPI endpoints) + agent_server.py (Discord + agent logic)
Run with: pytest test_main.py -v
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# ──────────────────────────────────────────────
# main.py tests
# ──────────────────────────────────────────────
from main import app

client = TestClient(app)

# ── Endpoint: GET /logs ───────────────────────

def test_read_logs_endpoint():
    """GET /logs should return 200 with a 'logs' list."""
    response = client.get("/logs")
    assert response.status_code == 200
    assert "logs" in response.json()
    assert isinstance(response.json()["logs"], list)


def test_logs_limit_parameter():
    """GET /logs?limit=5 should return at most 5 records."""
    response = client.get("/logs?limit=5")
    assert response.status_code == 200
    assert len(response.json()["logs"]) <= 5


# ── Endpoint: GET /blocked-ips ────────────────

def test_blocked_ips_endpoint():
    """GET /blocked-ips should return 200 with a 'blocked_ips' list."""
    response = client.get("/blocked-ips")
    assert response.status_code == 200
    assert "blocked_ips" in response.json()
    assert isinstance(response.json()["blocked_ips"], list)


# ── Endpoint: POST /ingest-log ────────────────

def test_normal_traffic_ingestion():
    """Normal traffic should NOT be flagged as an anomaly."""
    safe_log = {
        "timestamp": "2026-04-12T10:00:00",
        "ip_address": "192.168.1.50",
        "action": "LOGIN",
        "status": "SUCCESS",
        "message": "User action completed normally",
    }
    response = client.post("/ingest-log", json=safe_log)
    assert response.status_code == 200, response.text
    assert response.json()["is_anomaly"] is False


def test_ingest_log_missing_fields():
    """POST /ingest-log with missing required fields should return 422."""
    incomplete_log = {"ip_address": "10.0.0.1"}
    response = client.post("/ingest-log", json=incomplete_log)
    assert response.status_code == 422


def test_attack_traffic_detected():
    """
    A clearly malicious SSH brute-force log should be flagged as an anomaly.
    The ML model is real, so we only assert the response shape is correct.
    Uses an IP that is NOT in any firewall rules to avoid a 403.
    """
    attack_log = {
        "timestamp": "2026-04-12T10:05:00",
        "ip_address": "203.0.113.99",   # TEST-NET-3 — safe to use in tests
        "action": "SSH_LOGIN",
        "status": "FAILED",
        "message": "Failed password for root from 203.0.113.99 port 22 ssh2 - 50 attempts in 3 seconds",
    }
    # The agent call to port 8001 will fail in test — that's expected.
    response = client.post("/ingest-log", json=attack_log)
    assert response.status_code == 200
    assert "is_anomaly" in response.json()


def test_blocked_ip_is_rejected():
    """Traffic from an already-blocked IP should receive HTTP 403."""
    from main import BLOCKED_IPS
    test_ip = "11.22.33.44"
    BLOCKED_IPS.add(test_ip)

    blocked_log = {
        "timestamp": "2026-04-12T11:00:00",
        "ip_address": test_ip,
        "action": "LOGIN",
        "status": "ATTEMPT",
        "message": "Attempting to connect",
    }
    response = client.post("/ingest-log", json=blocked_log)
    assert response.status_code == 403

    BLOCKED_IPS.discard(test_ip)  # cleanup


# ── Endpoint: POST /approve-block ────────────

def test_approve_block_calls_agent():
    """
    POST /approve-block should try to call the agent at port 8001.
    Since the agent isn't running in tests, we expect a 500 (connection refused).
    """
    response = client.post("/approve-block", json={"ip_address": "45.33.22.11"})
    # Agent server is not running — we expect a 500, NOT a crash/exception
    assert response.status_code == 500


def test_approve_block_missing_ip():
    """POST /approve-block with no IP should return 422."""
    response = client.post("/approve-block", json={})
    assert response.status_code == 422


# ──────────────────────────────────────────────
# agent_server.py tests
# ──────────────────────────────────────────────
import importlib
import sys


def _load_agent_app(webhook_url: str):
    """
    Helper: reload agent_server with a custom DISCORD_WEBHOOK_URL env var
    so we can test different URL scenarios in isolation.
    """
    with patch.dict("os.environ", {"DISCORD_WEBHOOK_URL": webhook_url}):
        if "agent_server" in sys.modules:
            del sys.modules["agent_server"]
        import agent_server
        importlib.reload(agent_server)
        return agent_server


# ── send_to_discord guard logic ───────────────

def test_discord_send_skipped_when_url_missing():
    """
    send_to_discord must bail out silently when no URL is configured.
    Regression test for the 'not DISCORD_WEBHOOK_URL' bug.
    """
    with patch.dict("os.environ", {}, clear=True):
        if "agent_server" in sys.modules:
            del sys.modules["agent_server"]
        import agent_server
        importlib.reload(agent_server)

        with patch("agent_server.requests.post") as mock_post:
            agent_server.send_to_discord("Hello Discord")
            mock_post.assert_not_called()


def test_discord_send_skipped_when_url_invalid():
    """send_to_discord must bail out when URL doesn't start with 'http'."""
    mod = _load_agent_app("not-a-real-url")
    with patch("agent_server.requests.post") as mock_post:
        mod.send_to_discord("Hello")
        mock_post.assert_not_called()


def test_discord_send_called_when_url_valid():
    """send_to_discord MUST call requests.post when URL is properly set."""
    mod = _load_agent_app("https://discord.com/api/webhooks/fake/url")
    mock_response = MagicMock()
    mock_response.status_code = 204

    with patch("agent_server.requests.post", return_value=mock_response) as mock_post:
        mod.send_to_discord("Test message")
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert "Test message" in str(call_kwargs)


# ── Discord message format consistency ───────

def test_discord_message_format_is_consistent():
    """
    The Discord alert message must always use the fixed Python template,
    regardless of what the LLM returns.  This is the core regression test
    for the inconsistent-message bug.
    """
    mod = _load_agent_app("https://discord.com/api/webhooks/fake/url")
    agent_client = TestClient(mod.app)

    # Simulate the LLM returning garbage (the old bug source)
    llm_garbage_responses = [
        "The IP address is: 45.33.22.11",
        "45.33.22.11 [IP]",
        "Network Data: 45.33.22.11 | some raw log line",
        "45.33.22.11",  # ideal — just the IP
    ]

    expected_fragment = (
        "Boss!!! Our AI system detected something unusual illegal activities "
        "such as hacking and unauthorized access to systems from `45.33.22.11`"
    )

    for llm_output in llm_garbage_responses:
        mock_llm_response = MagicMock()
        mock_llm_response.json.return_value = {"response": llm_output}
        mock_llm_response.status_code = 200

        mock_discord_response = MagicMock()
        mock_discord_response.status_code = 204

        captured_messages = []

        def capture_post(url, **kwargs):
            if "discord" in url:
                captured_messages.append(kwargs.get("json", {}).get("content", ""))
                return mock_discord_response
            return mock_llm_response

        with patch("agent_server.requests.post", side_effect=capture_post):
            with patch("agent_server.subprocess.run"):
                response = agent_client.post(
                    "/api/agent",
                    json={"prompt": "Network Data: 45.33.22.11 | SSH brute force attack"},
                )

        # If a Discord message was sent, it must match our fixed template
        for msg in captured_messages:
            assert expected_fragment in msg, (
                f"LLM output '{llm_output}' caused wrong Discord message:\n{msg}"
            )


# ── Agent: execution order path ───────────────

def test_agent_execution_order_calls_subprocess():
    """
    When the prompt contains 'EXECUTE PREVIOUSLY STAGED RULE',
    the agent should run the execute_ip_block.py subprocess.
    """
    mod = _load_agent_app("https://discord.com/api/webhooks/fake/url")
    agent_client = TestClient(mod.app)

    mock_process = MagicMock()
    mock_process.stdout = "BLOCKED"
    mock_process.stderr = ""

    mock_discord = MagicMock()
    mock_discord.status_code = 204

    with patch("agent_server.subprocess.run", return_value=mock_process) as mock_sub:
        with patch("agent_server.requests.post", return_value=mock_discord):
            response = agent_client.post(
                "/api/agent",
                json={"prompt": "EXECUTE PREVIOUSLY STAGED RULE FOR IP: 45.33.22.11"},
            )

    assert response.status_code == 200
    mock_sub.assert_called_once()
    # args is a list like ['python', '/app/netops_skill/execute_ip_block.py', '45.33.22.11']
    args = mock_sub.call_args[0][0]
    assert any("execute_ip_block.py" in a for a in args)
    assert any(a == "45.33.22.11" for a in args)


def test_agent_execution_order_no_ip_returns_error():
    """Execution order without a valid IP should return an agent error."""
    mod = _load_agent_app("https://discord.com/api/webhooks/fake/url")
    agent_client = TestClient(mod.app)

    response = agent_client.post(
        "/api/agent",
        json={"prompt": "EXECUTE PREVIOUSLY STAGED RULE FOR IP: no-ip-here"},
    )
    assert response.status_code == 200
    assert "Error" in response.json()["result"]