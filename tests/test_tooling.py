"""Tests for the external-tool registry and installer hints."""

from __future__ import annotations

from openrecon.tooling import (
    TOOL_REGISTRY,
    install_hint,
    install_oss_tool,
    oss_tools,
)


def test_registry_covers_required_tools():
    # The auto-installable tools the user saw missing in `openrecon collectors`.
    for t in ("katana", "nuclei", "subfinder", "naabu"):
        assert t in TOOL_REGISTRY
        assert TOOL_REGISTRY[t]["kind"] in ("go", "pip")
    # SpiderFoot is documented but installed from GitHub, not pip - see the
    # 0.0.1-only PyPI placeholder that made `.[tools]` unsatisfiable.
    assert TOOL_REGISTRY["spiderfoot"]["kind"] == "manual"


def test_paid_api_tools_are_documented_not_fetched():
    for t in ("securitytrails", "hibp", "shodan", "virustotal"):
        assert TOOL_REGISTRY[t]["kind"] == "key"
        assert "env" in TOOL_REGISTRY[t] and "signup" in TOOL_REGISTRY[t]


def test_install_hint_is_actionable():
    assert "go install" in install_hint("nuclei")
    assert "SECURITYTRAILS_API_KEY" in install_hint("securitytrails")
    # SpiderFoot's hint is the GitHub install, not the (broken) pip extra.
    assert "github.com/smicallef/spiderfoot" in install_hint("spiderfoot")


def test_oss_tools_excludes_keys_and_manual():
    oss = oss_tools()
    assert "katana" in oss  # a go tool we can fetch
    assert "sqlmap" in oss  # the pip tool in the [tools] extra
    assert "securitytrails" not in oss  # key: never fetched
    assert "spiderfoot" not in oss  # manual: not auto-installable


def test_install_go_tool_without_golang_falls_back_to_manual(monkeypatch):
    # Simulate `go` not on PATH -> should report the manual command, not crash.
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _: None)
    ok, msg = install_oss_tool("katana")
    assert ok is False
    assert "go install" in msg


def test_install_unknown_tool_is_safe():
    ok, msg = install_oss_tool("does-not-exist")
    assert ok is False


def test_tool_path_override_wins(tmp_path):
    from openrecon.config import Config

    fake = tmp_path / "nuclei"
    fake.write_text("#!/bin/sh\n")
    cfg = Config(tool_paths={"nuclei": str(fake)})
    assert cfg.tool("nuclei") == str(fake)


def test_tool_found_in_go_bin_when_not_on_path(tmp_path, monkeypatch):
    """`go install` drops binaries in ~/go/bin, which is often not on PATH.

    openrecon must still find them there, or a freshly `make tools`'d machine
    reports every ProjectDiscovery tool as missing.
    """
    from openrecon.config import Config

    gobin = tmp_path / "go" / "bin"
    gobin.mkdir(parents=True)
    katana = gobin / "katana"
    katana.write_text("#!/bin/sh\n")
    katana.chmod(0o755)

    # A PATH that deliberately excludes the go bin dir, and no GOBIN/GOPATH.
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))
    monkeypatch.delenv("GOBIN", raising=False)
    monkeypatch.delenv("GOPATH", raising=False)
    monkeypatch.setattr("openrecon.config.Path.home", classmethod(lambda cls: tmp_path))

    cfg = Config()
    assert cfg.tool("katana") == str(katana)
    assert cfg.tool("does-not-exist") is None


def test_tool_respects_gobin_env(tmp_path, monkeypatch):
    from openrecon.config import Config

    gobin = tmp_path / "custom-gobin"
    gobin.mkdir()
    tool = gobin / "subfinder"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)

    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))
    monkeypatch.setenv("GOBIN", str(gobin))
    cfg = Config()
    assert cfg.tool("subfinder") == str(tool)
