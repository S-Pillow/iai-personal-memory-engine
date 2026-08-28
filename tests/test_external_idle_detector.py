from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from iai_mcp.idle_detector import IdleDetector


def _write_observation(path, *, idle_sec=0, observed_at=None, schema_version=1):
    if observed_at is None:
        observed_at = datetime.now(timezone.utc).isoformat()
    path.write_text(
        json.dumps(
            {
                "schema_version": schema_version,
                "idle_sec": idle_sec,
                "observed_at": observed_at,
                "source": "test-host-idle",
            }
        ),
        encoding="utf-8",
    )


def test_external_idle_fresh_observation_is_used(tmp_path, monkeypatch) -> None:
    observation = tmp_path / "host-idle.json"
    _write_observation(observation, idle_sec=1834)
    monkeypatch.setenv("IAI_MCP_EXTERNAL_IDLE_PATH", str(observation))

    assert IdleDetector().os_idle_time_sec() == (1834, "external_idle_file")


def test_external_idle_zero_is_valid_active_evidence(tmp_path, monkeypatch) -> None:
    observation = tmp_path / "host-idle.json"
    _write_observation(observation, idle_sec=0)
    monkeypatch.setenv("IAI_MCP_EXTERNAL_IDLE_PATH", str(observation))

    assert IdleDetector().os_idle_time_sec() == (0, "external_idle_file")


def test_external_idle_stale_observation_falls_back(tmp_path, monkeypatch) -> None:
    observation = tmp_path / "host-idle.json"
    stale = datetime.now(timezone.utc) - timedelta(seconds=120)
    _write_observation(observation, idle_sec=7200, observed_at=stale.isoformat())
    monkeypatch.setenv("IAI_MCP_EXTERNAL_IDLE_PATH", str(observation))
    monkeypatch.setattr("iai_mcp.idle_detector.platform.system", lambda: "Linux")
    monkeypatch.setattr(IdleDetector, "_logind_session_paths", lambda self: [])

    assert IdleDetector().os_idle_time_sec() == (None, None)


def test_external_idle_future_observation_falls_back(tmp_path, monkeypatch) -> None:
    observation = tmp_path / "host-idle.json"
    future = datetime.now(timezone.utc) + timedelta(seconds=30)
    _write_observation(observation, idle_sec=7200, observed_at=future.isoformat())
    monkeypatch.setenv("IAI_MCP_EXTERNAL_IDLE_PATH", str(observation))
    monkeypatch.setattr("iai_mcp.idle_detector.platform.system", lambda: "Linux")
    monkeypatch.setattr(IdleDetector, "_logind_session_paths", lambda self: [])

    assert IdleDetector().os_idle_time_sec() == (None, None)


def test_external_idle_naive_timestamp_falls_back(tmp_path, monkeypatch) -> None:
    observation = tmp_path / "host-idle.json"
    naive = datetime.now().replace(microsecond=0).isoformat()
    _write_observation(observation, idle_sec=7200, observed_at=naive)
    monkeypatch.setenv("IAI_MCP_EXTERNAL_IDLE_PATH", str(observation))
    monkeypatch.setattr("iai_mcp.idle_detector.platform.system", lambda: "Linux")
    monkeypatch.setattr(IdleDetector, "_logind_session_paths", lambda self: [])

    assert IdleDetector().os_idle_time_sec() == (None, None)


@pytest.mark.parametrize(
    "idle_sec,schema_version",
    [
        (-1, 1),
        (True, 1),
        ("1800", 1),
        (float("nan"), 1),
        (float("inf"), 1),
        (1800, 2),
        (1800, True),
    ],
)
def test_external_idle_invalid_values_fall_back(
    tmp_path, monkeypatch, idle_sec, schema_version
) -> None:
    observation = tmp_path / "host-idle.json"
    _write_observation(
        observation,
        idle_sec=idle_sec,
        schema_version=schema_version,
    )
    monkeypatch.setenv("IAI_MCP_EXTERNAL_IDLE_PATH", str(observation))
    monkeypatch.setattr("iai_mcp.idle_detector.platform.system", lambda: "Linux")
    monkeypatch.setattr(IdleDetector, "_logind_session_paths", lambda self: [])

    assert IdleDetector().os_idle_time_sec() == (None, None)


def test_external_idle_malformed_json_falls_back(tmp_path, monkeypatch) -> None:
    observation = tmp_path / "host-idle.json"
    observation.write_text("{not-json", encoding="utf-8")
    monkeypatch.setenv("IAI_MCP_EXTERNAL_IDLE_PATH", str(observation))
    monkeypatch.setattr("iai_mcp.idle_detector.platform.system", lambda: "Linux")
    monkeypatch.setattr(IdleDetector, "_logind_session_paths", lambda self: [])

    assert IdleDetector().os_idle_time_sec() == (None, None)


def test_external_idle_missing_file_falls_back(tmp_path, monkeypatch) -> None:
    observation = tmp_path / "missing.json"
    monkeypatch.setenv("IAI_MCP_EXTERNAL_IDLE_PATH", str(observation))
    monkeypatch.setattr("iai_mcp.idle_detector.platform.system", lambda: "Linux")
    monkeypatch.setattr(IdleDetector, "_logind_session_paths", lambda self: [])

    assert IdleDetector().os_idle_time_sec() == (None, None)


def test_external_idle_opt_in_absent_preserves_native_linux_path(monkeypatch) -> None:
    monkeypatch.delenv("IAI_MCP_EXTERNAL_IDLE_PATH", raising=False)
    monkeypatch.setattr("iai_mcp.idle_detector.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        IdleDetector,
        "_logind_session_paths",
        lambda self: ["/org/freedesktop/login1/session/c2"],
    )
    monkeypatch.setattr(IdleDetector, "_logind_aggregate_idle", lambda self, paths: 321)

    assert IdleDetector().os_idle_time_sec() == (321, "logind")


def test_external_idle_status_is_reported_as_available(tmp_path, monkeypatch) -> None:
    observation = tmp_path / "host-idle.json"
    _write_observation(observation, idle_sec=42)
    monkeypatch.setenv("IAI_MCP_EXTERNAL_IDLE_PATH", str(observation))
    monkeypatch.setattr("iai_mcp.idle_detector.platform.system", lambda: "Linux")

    status = IdleDetector().status()
    detail, verdict = IdleDetector().describe()

    assert status.hid_idle_sec == 42
    assert status.available_signals == ["external_idle_file"]
    assert verdict == "PASS"
    assert "external host idle: 42s" in detail
