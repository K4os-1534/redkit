"""Tests for redkit.cli — version, module listing, headless mode, session resume."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from redkit.cli import main


@pytest.fixture
def xss_server():
    """Local HTTP server reflecting the q parameter (XSS target)."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code, body):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            if urlparse(self.path).path == "/search":
                self._send(200, f"<html><body>Results for {q}</body></html>")
            else:
                self._send(200, "not found")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "RedKit" in capsys.readouterr().out


def test_cli_list_modules(capsys):
    rc = main(["--list-modules"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "XSS Tester" in out
    assert "Subdomain Enumerator" in out


def test_cli_headless_run_generates_report(xss_server, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = main(
        [
            "--no-tui",
            "--target",
            f"{xss_server}/search",
            "--module",
            "XSS Tester",
            "--opt",
            "param=q",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "1 finding(s) recorded" in out
    reports = list(Path("reports").glob("redkit_*.html"))
    assert len(reports) == 1
    assert (Path("reports") / reports[0].name.replace(".html", ".json")).is_file()


def test_cli_headless_no_report_flag(xss_server, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = main(
        [
            "--no-tui",
            "--target",
            f"{xss_server}/search",
            "--module",
            "XSS Tester",
            "--opt",
            "param=q",
            "--no-report",
        ]
    )
    assert rc == 0
    assert not Path("reports").exists()


def test_cli_headless_requires_target_and_module(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = main(["--no-tui", "--module", "XSS Tester"])
    assert rc == 1


def test_cli_headless_unknown_module(xss_server, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = main(["--no-tui", "--target", xss_server, "--module", "No Such Module"])
    assert rc == 1


def test_cli_headless_bad_opt(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = main(
        [
            "--no-tui",
            "--target",
            "https://example.com",
            "--module",
            "XSS Tester",
            "--opt",
            "bogus=1",
        ]
    )
    assert rc == 1


def test_cli_resume_missing_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = main(["--resume", str(tmp_path / "missing.json")])
    assert rc == 1


def test_cli_resume_saved_session(xss_server, tmp_path, monkeypatch, capsys):
    """A session saved by a headless run must be loadable via --resume (list-modules path)."""
    monkeypatch.chdir(tmp_path)
    rc = main(
        [
            "--no-tui",
            "--target",
            f"{xss_server}/search",
            "--module",
            "XSS Tester",
            "--opt",
            "param=q",
            "--no-report",
            "--save",
            str(tmp_path / "sess.json"),
        ]
    )
    assert rc == 0

    from redkit.core.session import Session

    restored = Session.load(tmp_path / "sess.json")
    assert restored.target is not None
    assert len(restored.get_all_findings()) == 1


# ---------------------------------------------------------------------
# New CLI conveniences (2.1)
# ---------------------------------------------------------------------


def test_cli_init_config_creates_and_refuses_overwrite(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["--init-config"]) == 0
    cfg_file = tmp_path / "config.yaml"
    assert cfg_file.is_file()
    content = cfg_file.read_text(encoding="utf-8")
    assert "ui_pause" in content and "save_history" in content
    # Second run must refuse to overwrite
    assert main(["--init-config"]) == 1
    assert "already exists" in capsys.readouterr().out


def test_cli_last_without_sessions_fails(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["--last"]) == 1
    assert "No redkit_session" in capsys.readouterr().out


def test_find_last_session_picks_newest(tmp_path, monkeypatch):
    import os

    monkeypatch.chdir(tmp_path)
    older = tmp_path / "redkit_session_a_1.json"
    newer = tmp_path / "redkit_session_b_2.json"
    older.write_text("{}")
    newer.write_text("{}")
    os.utime(older, (1000, 1000))
    os.utime(newer, (2000, 2000))

    from redkit.cli import _find_last_session

    assert _find_last_session() == newer


def test_cli_help_options_exact_and_fuzzy(capsys):
    assert main(["--module", "XSS Tester", "--help-options"]) == 0
    out = capsys.readouterr().out
    assert "XSS Tester — Options" in out
    assert "param" in out

    # Substring match resolves to the single XSS module
    assert main(["--module", "xss", "--help-options"]) == 0

    # Ambiguous substring lists candidates and fails
    assert main(["--module", "tester", "--help-options"]) == 1
    out = capsys.readouterr().out
    assert "Ambiguous" in out and "XSS Tester" in out and "SQLi Tester" in out

    # Unknown module lists available modules
    assert main(["--module", "nope", "--help-options"]) == 1
    assert "Available modules" in capsys.readouterr().out


def test_cli_help_options_requires_module(capsys):
    assert main(["--help-options"]) == 1


def test_cli_headless_fuzzy_module_name(xss_server, tmp_path, monkeypatch, capsys):
    """'xss' resolves to 'XSS Tester' in headless mode too."""
    monkeypatch.chdir(tmp_path)
    rc = main(
        [
            "--no-tui",
            "--target",
            f"{xss_server}/search",
            "--module",
            "xss",
            "--opt",
            "param=q",
            "--no-report",
        ]
    )
    assert rc == 0
    assert "Potential reflected XSS" in capsys.readouterr().out


def test_cli_verbose_flag_runs(xss_server, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = main(["--list-modules", "--verbose"])
    assert rc == 0
