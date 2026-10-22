"""
Tests for Wi-Fi Security Diagnostics and NMCLI output
"""

from core.job_manager import JobManager
from modules.wifi_security.service import WiFiSecurityService


def test_wifi_diagnostics_structure():
    diag = WiFiSecurityService.get_adapter_diagnostics()
    assert isinstance(diag, dict)
    assert "interfaces" in diag
    assert "has_wireless" in diag
    assert "summary" in diag


def test_parse_nmcli_wifi_output():
    stdout = """
LabGuestNet:00:11:22:33:44:55:6:2437 MHz:54 Mbit/s:82:WPA2
CorpCorp_5G:66:77:88:99:AA:BB:36:5180 MHz:400 Mbit/s:65:WPA2 WPA3
"""
    parsed = JobManager.parse_tool_output("nmcli", stdout, "")
    assert parsed["count"] == 2
    assert parsed["items"][0]["ssid"] == "LabGuestNet"
    assert parsed["items"][0]["bssid"] == "00:11:22:33:44:55"
    assert parsed["items"][1]["ssid"] == "CorpCorp_5G"
