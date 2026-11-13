"""Tests for redkit.core.engine — discovery, external modules, dedupe, config injection."""

from redkit.core.engine import Engine

CUSTOM_MODULE_SRC = (
    "from redkit.modules.base_module import BaseModule\n"
    "class MyCustom(BaseModule):\n"
    "    name = 'My Custom'\n"
    "    description = 'external test module'\n"
    "    author = 't'\n"
    "    category = 'custom'\n"
    "    options = {}\n"
    "    def run(self):\n"
    "        pass\n"
)

DUPLICATE_MODULE_SRC = (
    "from redkit.modules.base_module import BaseModule\n"
    "class Dup(BaseModule):\n"
    "    name = 'XSS Tester'\n"
    "    description = 'duplicate of bundled module'\n"
    "    author = 't'\n"
    "    options = {}\n"
    "    def run(self):\n"
    "        pass\n"
)


def test_engine_discovers_bundled_modules():
    engine = Engine(config={})
    engine.discover()
    assert engine.count() == 27
    assert engine.get_module_by_name("xss tester") is not None
    assert set(engine.get_modules_by_category()) == {"recon", "vuln_scan", "auth", "misconfig"}


def test_engine_get_module_by_index():
    engine = Engine(config={})
    engine.discover()
    assert engine.get_module_by_index(1) is engine.get_all_modules()[0]
    assert engine.get_module_by_index(999) is None


def test_engine_discovers_external_modules(tmp_path, monkeypatch):
    ext = tmp_path / "modules" / "custom"
    ext.mkdir(parents=True)
    (ext / "my_mod.py").write_text(CUSTOM_MODULE_SRC)
    monkeypatch.chdir(tmp_path)

    engine = Engine(config={})
    engine.discover()
    assert engine.get_module_by_name("My Custom") is not None
    assert engine.count() == 28
    assert "custom" in engine.get_modules_by_category()


def test_engine_dedupes_by_name(tmp_path, monkeypatch):
    ext = tmp_path / "modules" / "vuln_scan"
    ext.mkdir(parents=True)
    (ext / "dup.py").write_text(DUPLICATE_MODULE_SRC)
    monkeypatch.chdir(tmp_path)

    engine = Engine(config={})
    engine.discover()
    assert engine.count() == 27
    # The bundled definition won
    assert engine.get_module_by_name("XSS Tester").description.startswith("Tests a query parameter")


def test_engine_injects_config_into_modules():
    engine = Engine(config={"default_timeout": 42})
    engine.discover()
    mod = engine.get_module_by_name("XSS Tester")
    assert mod.get_config("default_timeout") == 42
