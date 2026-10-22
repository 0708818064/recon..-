"""
Tests for Safe Command Builder
"""

import pytest
from core.command_builder import CommandBuilder


def test_sanitize_arg_blocks_injection():
    """Ensure shell metacharacters raise ValueError."""
    dangerous = [
        "target.com; rm -rf /",
        "example.com && whoami",
        "test.org | cat /etc/passwd",
        "target.com `id`",
        "test.com $(reboot)",
        "target.com > output.txt"
    ]
    for arg in dangerous:
        with pytest.raises(ValueError):
            CommandBuilder.sanitize_arg(arg)


def test_build_dig_command():
    cmd = CommandBuilder.build_dig("example.com", "MX")
    assert isinstance(cmd, list)
    assert cmd[-2] == "example.com"
    assert cmd[-1] == "MX"


def test_build_curl_command():
    cmd = CommandBuilder.build_curl("https://example.com")
    assert isinstance(cmd, list)
    assert "-I" in cmd
    assert "https://example.com" in cmd
