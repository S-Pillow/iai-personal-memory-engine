from __future__ import annotations

from pathlib import Path

import iai_mcp.daemon as daemon
import iai_mcp.daemon._watchdog as watchdog


class _FakeSignal:
    SIGTERM = 15
    SIGINT = 2
    SIG_DFL = 0

    def __init__(self, *, sighup: int | None) -> None:
        self.calls: list[int] = []
        if sighup is not None:
            self.SIGHUP = sighup

    def signal(self, signum: int, _handler) -> None:
        self.calls.append(signum)


def _install_with_fake_signal(monkeypatch, tmp_path: Path, *, sighup: int | None) -> list[int]:
    fake = _FakeSignal(sighup=sighup)
    monkeypatch.setattr(daemon, "signal", fake)
    monkeypatch.setattr(
        watchdog,
        "_watchdog_log_path",
        lambda: tmp_path / "watchdog.log",
    )

    daemon._install_boot_signal_trace()
    return fake.calls


def test_install_boot_signal_trace_skips_missing_sighup(monkeypatch, tmp_path: Path) -> None:
    assert _install_with_fake_signal(monkeypatch, tmp_path, sighup=None) == [15, 2]


def test_install_boot_signal_trace_keeps_sighup_when_available(monkeypatch, tmp_path: Path) -> None:
    assert _install_with_fake_signal(monkeypatch, tmp_path, sighup=1) == [15, 2, 1]
