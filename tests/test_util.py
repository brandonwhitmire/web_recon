import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from web_recon.util import (
    detect_attacker_ip,
    host_port_from_target,
    source_ip_toward,
)


class HostPortTests(unittest.TestCase):
    def test_hostname_local(self):
        self.assertEqual(host_port_from_target("http://hostname.local"), ("hostname.local", 80))
        self.assertEqual(host_port_from_target("http://hostname.local/app"), ("hostname.local", 80))

    def test_https_default_port(self):
        self.assertEqual(host_port_from_target("https://box.web/login"), ("box.web", 443))

    def test_explicit_port(self):
        self.assertEqual(host_port_from_target("http://hostname.local:8080/x"), ("hostname.local", 8080))

    def test_bare_host(self):
        self.assertEqual(host_port_from_target("hostname.local"), ("hostname.local", 80))

    def test_empty(self):
        self.assertEqual(host_port_from_target(None), (None, 80))
        self.assertEqual(host_port_from_target("  "), (None, 80))


class SourceIpTests(unittest.TestCase):
    def test_udp_connect_uses_os_route(self):
        sock = MagicMock()
        sock.getsockname.return_value = ("192.168.1.50", 54321)
        with patch("web_recon.util.socket.socket", return_value=sock) as m:
            ip = source_ip_toward("hostname.local", 80)
        m.assert_called()
        sock.connect.assert_called_with(("hostname.local", 80))
        self.assertEqual(ip, "192.168.1.50")

    def test_loopback_skipped(self):
        sock = MagicMock()
        sock.getsockname.return_value = ("127.0.0.1", 54321)
        with patch("web_recon.util.socket.socket", return_value=sock):
            self.assertIsNone(source_ip_toward("127.0.0.1", 80))

    def test_ipv4_mapped_normalized(self):
        sock = MagicMock()
        sock.getsockname.return_value = ("::ffff:10.10.14.8", 54321)
        with patch("web_recon.util.socket.socket", return_value=sock):
            self.assertEqual(source_ip_toward("box.web", 80), "10.10.14.8")

    def test_detect_uses_target_before_vpn(self):
        with patch("web_recon.util.source_ip_toward", return_value="10.10.14.8") as src:
            with patch("web_recon.util._iface_ipv4", return_value="10.8.0.2"):
                ip = detect_attacker_ip("http://hostname.local/")
        src.assert_called_once_with("hostname.local", 80)
        self.assertEqual(ip, "10.10.14.8")

    def test_detect_falls_back_to_tun0(self):
        with patch("web_recon.util.source_ip_toward", return_value=None):
            with patch("web_recon.util._iface_ipv4", side_effect=lambda iface: "10.10.14.8" if iface == "tun0" else None):
                self.assertEqual(detect_attacker_ip("http://hostname.local/"), "10.10.14.8")


if __name__ == "__main__":
    unittest.main()
