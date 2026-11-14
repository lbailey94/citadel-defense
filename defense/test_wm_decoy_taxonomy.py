"""Unit tests for wm_decoy_taxonomy helpers and backward-compatible contracts."""

import pathlib
import sys

DEFENSE_DIR = pathlib.Path(__file__).resolve().parent
if str(DEFENSE_DIR) not in sys.path:
    sys.path.insert(0, str(DEFENSE_DIR))

import wm_decoy_taxonomy as tax


def test_automated_ssh_banner_detection():
    for banner in (
        "SSH-2.0-Go",
        "SSH-2.0-libssh_0.9.5",
        "SSH-2.0-Nmap-NSE",
        "SSH-2.0-zgrab2_0.1",
        "SSH-2.0-masscan/1.3",
        "SSH-2.0-paramiko_2.12.0",
        "SSH-2.0-asyncssh_2.14.0",
    ):
        assert tax.is_automated_ssh_banner(banner) is True

    for benign in (
        "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
        "SSH-2.0-PuTTY_Release_0.80",
        "",
        None,
    ):
        assert tax.is_automated_ssh_banner(benign) is False


def test_classify_proxy_port():
    assert tax.classify_proxy_port(443) == "https_tunnel"
    assert tax.classify_proxy_port("443") == "https_tunnel"
    assert tax.classify_proxy_port(53) == "dns_probe"
    assert tax.classify_proxy_port(3389) == "rdp_pivot"
    assert tax.classify_proxy_port(25) == "smtp_relay"
    assert tax.classify_proxy_port(587) == "smtp_relay"
    assert tax.classify_proxy_port(80) == "http_tunnel"
    assert tax.classify_proxy_port(1080) == "socks_pivot"
    assert tax.classify_proxy_port(3306) == "db_pivot"
    assert tax.classify_proxy_port(54321) == "other"
    assert tax.classify_proxy_port(None) == "other"
    assert tax.classify_proxy_port("not-a-port") == "other"


def test_taxonomy_contracts_preserved():
    assert tax.is_protected("152.53.195.47") is True
    assert tax.is_protected("174.56.168.79") is True
    assert tax.is_protected("198.51.100.10") is True  # RFC 5737 TEST-NET (non-global)
    assert tax.is_protected("45.33.32.10") is False
    assert tax.classify_cowrie_event("cowrie.session.connect") is None
    assert tax.classify_cowrie_event("cowrie.login.failed") == tax.SSH_SESSION
    assert tax.classify_cowrie_event("cowrie.login.success") == tax.SSH_SESSION
    assert tax.classify_cowrie_event("cowrie.command.input") == tax.SSH_ACTION
    assert tax.classify_cowrie_event("cowrie.direct-tcpip.request") == tax.SSH_ACTION
    assert tax.SSH_SCANNER_BURST in tax.ALL_CLASSES
