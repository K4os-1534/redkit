"""Tests for redkit.core.tui — findings table rendering."""

from rich.console import Console

from redkit.core.models import Finding
from redkit.core.tui import render_findings_table


def _capture(findings, **kwargs) -> str:
    console = Console(record=True, width=200)
    render_findings_table(console, findings, **kwargs)
    return console.export_text()


def test_render_findings_table_rows():
    findings = [
        Finding(type="XSS", severity="HIGH", title="reflected payload", detail="d"),
        Finding(type="SQL Injection", severity="CRITICAL", title="error-based", detail="d"),
    ]
    text = _capture(findings)
    assert "reflected payload" in text
    assert "error-based" in text
    assert "HIGH" in text
    assert "CRITICAL" in text


def test_render_findings_table_module_column():
    findings = [Finding(type="XSS", severity="LOW", title="t", detail="d", module="XSS Tester")]
    text = _capture(findings, show_module=True)
    assert "XSS Tester" in text


def test_render_findings_table_max_rows():
    findings = [Finding(type="T", severity="INFO", title=f"f{i}", detail="d") for i in range(10)]
    text = _capture(findings, max_rows=3)
    assert "f0" in text
    assert "f2" in text
    assert "f3" not in text


# ---------------------------------------------------------------------
# Summary bars and detail panel
# ---------------------------------------------------------------------


def test_severity_summary_renders_counts():
    from redkit.core.tui import TUI

    findings = [
        Finding(type="X", severity="CRITICAL", title="a", detail=""),
        Finding(type="X", severity="CRITICAL", title="b", detail=""),
        Finding(type="X", severity="INFO", title="c", detail=""),
    ]
    console = Console(record=True, width=200)
    tui = TUI(session=None, engine=None, config={})
    import redkit.core.tui as tui_mod

    orig_console = tui_mod.console
    tui_mod.console = console
    try:
        tui._render_severity_summary(findings)
    finally:
        tui_mod.console = orig_console
    text = console.export_text()
    assert "CRITICAL" in text and "INFO" in text and "█" in text


def test_finding_detail_panel_shows_everything():
    import redkit.core.tui as tui_mod
    from redkit.core.tui import TUI

    finding = Finding(
        type="XSS",
        severity="HIGH",
        title="reflected",
        detail="the detail",
        evidence="<script>x</script>",
        module="XSS Tester",
        cvss=6.1,
    )
    console = Console(record=True, width=200)
    tui = TUI(session=None, engine=None, config={})
    orig_console = tui_mod.console
    tui_mod.console = console
    try:
        tui._finding_detail_panel(finding, 3)
    finally:
        tui_mod.console = orig_console
    text = console.export_text()
    assert "Finding #3" in text
    assert "the detail" in text and "<script>x</script>" in text
    assert "6.1" in text and "XSS Tester" in text
    assert "Remediation" in text  # XSS has remediation guidance


# ---------------------------------------------------------------------
# Interactive flows (fake Prompt + captured console)
# ---------------------------------------------------------------------


class FakePrompt:
    """Replaces rich Prompt in the tui module with canned answers."""

    def __init__(self, answers):
        self.answers = list(answers)

    def ask(self, prompt="", console=None, **kwargs):
        assert self.answers, f"Unexpected Prompt.ask call: {prompt!r}"
        return self.answers.pop(0)


def make_tui(tmp_path, monkeypatch, answers=None, **config_overrides):
    answers = answers or []
    import redkit.core.tui as tui_mod
    from redkit.core.engine import Engine
    from redkit.core.session import Session
    from redkit.core.tui import TUI

    captured = Console(record=True, width=200)
    monkeypatch.setattr(tui_mod, "console", captured)
    monkeypatch.setattr(tui_mod, "Prompt", FakePrompt(answers))

    config = {
        "ui_pause": False,
        "ui_clear_screen": False,
        "ask_authorization": False,
        "save_history": True,
        "history_file": str(tmp_path / "history.json"),
    }
    config.update(config_overrides)

    session = Session()
    engine = Engine(config=config)
    engine.discover()
    return TUI(session=session, engine=engine, config=config), captured


def patch_run(monkeypatch, module, finding_type="XSS", severity="HIGH"):
    """Replace module.run like a real module: clear, then record one finding."""

    def fake_run():
        module.clear_findings()
        module.add_finding(finding_type, severity, "found", "d")

    monkeypatch.setattr(module, "run", fake_run)


def test_execute_module_runs_without_prompts_when_authz_disabled(tmp_path, monkeypatch):
    tui, captured = make_tui(tmp_path, monkeypatch)
    tui.session.set_target("https://example.com/search?q=1")
    module = tui.engine.get_module_by_name("XSS Tester")
    module.set_option("param", "q")
    patch_run(monkeypatch, module)

    tui._execute_module(module)

    assert len(tui.session.get_all_findings()) == 1
    assert "Scan complete" in captured.export_text()


def test_execute_module_prompts_for_missing_required_option(tmp_path, monkeypatch):
    tui, _ = make_tui(tmp_path, monkeypatch)
    tui.session.set_target("https://example.com/search?q=1")
    module = tui.engine.get_module_by_name("XSS Tester")
    patch_run(monkeypatch, module)

    # _execute_module prompts for 'param' (canned: "q"); nothing else required
    tui.config["ui_pause"] = False
    import redkit.core.tui as tui_mod

    # Rebuild prompt with answers: param then nothing else
    monkeypatch.setattr(tui_mod, "Prompt", FakePrompt(["q"]))
    tui._execute_module(module)
    assert module.get_option("param") == "q"
    assert len(tui.session.get_all_findings()) == 1


def test_execute_module_authorization_declined_cancels_scan(tmp_path, monkeypatch):
    tui, _ = make_tui(tmp_path, monkeypatch, ask_authorization=True)
    tui.session.set_target("https://example.com/search?q=1")
    module = tui.engine.get_module_by_name("XSS Tester")
    module.set_option("param", "q")
    patch_run(monkeypatch, module)

    import redkit.core.tui as tui_mod

    monkeypatch.setattr(tui_mod, "Prompt", FakePrompt(["q", "n"]))
    tui._execute_module(module)
    assert tui.session.get_all_findings() == []
    assert not tui._authorization_confirmed


def test_execute_module_authorization_confirmed_once(tmp_path, monkeypatch):
    tui, _ = make_tui(tmp_path, monkeypatch, ask_authorization=True)
    tui.session.set_target("https://example.com/search?q=1")
    module = tui.engine.get_module_by_name("XSS Tester")
    patch_run(monkeypatch, module)

    import redkit.core.tui as tui_mod

    # "q" answers the missing-option prompt for param, "y" the authorization
    # prompt; the second run needs no new answers (confirmed once per session)
    monkeypatch.setattr(tui_mod, "Prompt", FakePrompt(["q", "y"]))
    tui._execute_module(module)
    assert tui._authorization_confirmed
    tui._execute_module(module)
    assert len(tui.session.get_all_findings()) == 2


def test_auth_category_requires_extra_confirmation(tmp_path, monkeypatch):
    tui, _ = make_tui(tmp_path, monkeypatch)
    tui.session.set_target("https://example.com/login")
    module = tui.engine.get_module_by_name("Default Credentials Checker")
    module.set_option("failure_string", "Invalid credentials")
    patch_run(monkeypatch, module, "Default Credentials", "CRITICAL")

    import redkit.core.tui as tui_mod

    # authz is disabled; the auth-attack confirm is answered "n" → skipped
    monkeypatch.setattr(tui_mod, "Prompt", FakePrompt(["n"]))
    tui._execute_module(module)
    assert tui.session.get_all_findings() == []
    assert "Module skipped" in tui_mod.console.export_text()


def test_profile_run_shares_options_and_records_history(tmp_path, monkeypatch):
    tui, captured = make_tui(tmp_path, monkeypatch)
    tui.session.set_target("https://example.com/search?q=1")

    import redkit.core.tui as tui_mod

    for name in ("XSS Tester", "SQLi Tester", "LFI Tester"):
        module = tui.engine.get_module_by_name(name)
        patch_run(monkeypatch, module, "XSS" if name == "XSS Tester" else name.split()[0], "HIGH")

    # Answers: profile #3 (Vulnerability Sweep), param="q" (asked once), authz n/a
    monkeypatch.setattr(tui_mod, "Prompt", FakePrompt(["3", "q"]))
    tui._menu_run_profile()

    assert len(tui.session.get_all_findings()) == 3
    text = captured.export_text()
    assert "Vulnerability Sweep" in text and "complete" in text

    # Options were persisted to the configured history file
    from redkit.core.history import load_module_options

    saved = load_module_options(__import__("pathlib").Path(tui.config["history_file"]), "XSS Tester")
    assert saved.get("param") == "q"


def test_target_param_hints_from_session_url(tmp_path, monkeypatch):
    tui, _ = make_tui(tmp_path, monkeypatch)
    assert tui._target_param_hints() == []
    tui.session.set_target("https://example.com/page?q=1&page=2")
    assert tui._target_param_hints() == ["q", "page"]
