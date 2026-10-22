"""
Tests for Central Tool Manager
"""

import pytest
from core.tool_manager import ToolManager, ToolInfo


def test_tool_registry_integrity():
    """Ensure all tools in registry contain required attributes."""
    assert len(ToolManager.TOOL_REGISTRY) >= 15
    for name, tool in ToolManager.TOOL_REGISTRY.items():
        assert "display_name" in tool
        assert "category" in tool
        assert tool["category"] in ["web_recon", "wifi_security"]
        assert "purpose" in tool
        assert "installation_methods" in tool
        assert isinstance(tool["installation_methods"], list)
        assert len(tool["installation_methods"]) >= 1


def test_check_tool_returns_toolinfo():
    """Ensure check_tool returns valid ToolInfo dataclass."""
    info = ToolManager.check_tool("nmap")
    assert isinstance(info, ToolInfo)
    assert info.name == "nmap"
    assert info.category == "web_recon"
    assert info.status in ["READY", "MISSING", "ERROR"]


def test_unknown_tool_returns_error():
    """Ensure querying an unknown tool does not crash and reports error."""
    info = ToolManager.check_tool("nonexistent_security_tool_xyz")
    assert info.status == "ERROR"
    assert "not registered" in info.error_message


def test_get_tools_by_category():
    """Test filtering tools by module category."""
    web_tools = ToolManager.get_tools_by_category("web_recon")
    wifi_tools = ToolManager.get_tools_by_category("wifi_security")

    assert len(web_tools) > 0
    assert len(wifi_tools) > 0
    assert all(t.category == "web_recon" for t in web_tools)
    assert all(t.category == "wifi_security" for t in wifi_tools)
