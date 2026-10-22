"""
Tests for Installation Manager
"""

from core.installation_manager import InstallationManager


def test_environment_diagnostics():
    env = InstallationManager.get_environment_diagnostics()
    assert "python3" in env
    assert env["python3"]["available"] is True
    assert "apt" in env


def test_get_instructions_for_nmap():
    inst = InstallationManager.get_instructions("nmap")
    assert inst["tool_name"] == "nmap"
    assert "apt" in inst["recommended_method"]
    assert "sudo apt" in inst["recommended_command"]
    assert inst["verification_command"] == "nmap --version"
