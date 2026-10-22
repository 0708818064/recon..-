"""
Tests for Web Reconnaissance & Output Parsers
"""

from core.job_manager import JobManager


def test_parse_subdomain_output():
    stdout = """
sub1.example.com
sub2.example.com
sub3.example.com
sub1.example.com
"""
    parsed = JobManager.parse_tool_output("subfinder", stdout, "")
    assert parsed["count"] == 3
    assert "sub1.example.com" in parsed["items"]
    assert "sub2.example.com" in parsed["items"]


def test_parse_nmap_output():
    stdout = """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-22
Nmap scan report for scanme.nmap.org (45.33.32.156)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 6.6.1p1 Ubuntu
80/tcp    open  http       Apache httpd 2.4.7
9929/tcp  open  nping-echo Nping echo
Nmap done: 1 IP address (1 host up) scanned in 2.12 seconds
"""
    parsed = JobManager.parse_tool_output("nmap", stdout, "")
    assert parsed["count"] == 3
    ports = [p["port"] for p in parsed["items"]]
    assert "22/tcp" in ports
    assert "80/tcp" in ports


def test_parse_httpx_output():
    stdout = """
https://example.com [200] [Example Domain]
http://example.com [301] [Moved Permanently]
"""
    parsed = JobManager.parse_tool_output("httpx", stdout, "")
    assert parsed["count"] == 2
    assert parsed["items"][0]["status_code"] == "200"
    assert parsed["items"][0]["title"] == "Example Domain"
