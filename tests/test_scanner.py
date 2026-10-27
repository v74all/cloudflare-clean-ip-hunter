"""python3 -m unittest discover -s tests   (no network needed)"""
import base64
import ipaddress
import json
import os
import random
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qsl, unquote, urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import scanner  # noqa: E402


def vmess(d):
    return "vmess://" + base64.b64encode(json.dumps(d).encode()).decode()


class Links(unittest.TestCase):
    def test_vless_ws_tls_gets_sni_and_host(self):
        link = "vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443?encryption=none&security=tls&type=ws&path=%2Fws%3Fed%3D2048#my%20server"
        self.assertEqual(scanner.link_target(link), ("vless", "cdn.example.com", "cdn.example.com", 443, True))
        out = scanner.rewrite_link(link, "104.16.1.2")
        sp = urlsplit(out)
        q = dict(parse_qsl(sp.query))
        self.assertEqual(sp.hostname, "104.16.1.2")
        self.assertEqual(sp.port, 443)
        self.assertEqual(q["sni"], "cdn.example.com")
        self.assertEqual(q["host"], "cdn.example.com")
        self.assertEqual(q["path"], "/ws?ed=2048")
        self.assertEqual(unquote(sp.fragment), "my server-104.16.1.2")
        self.assertTrue(out.startswith("vless://11111111-2222-3333-4444-555555555555@"))

    def test_existing_sni_and_host_are_kept(self):
        link = "vless://id@1.2.3.4:2053?security=tls&sni=a.example.com&host=b.example.com&type=xhttp#x"
        self.assertEqual(scanner.link_target(link), ("vless", "a.example.com", "b.example.com", 2053, True))
        q = dict(parse_qsl(urlsplit(scanner.rewrite_link(link, "172.64.0.9")).query))
        self.assertEqual((q["sni"], q["host"]), ("a.example.com", "b.example.com"))

    def test_trojan_defaults_to_tls(self):
        link = "trojan://pass@t.example.com:8443?type=grpc&serviceName=s#t"
        self.assertEqual(scanner.link_target(link)[4], True)
        q = dict(parse_qsl(urlsplit(scanner.rewrite_link(link, "104.24.0.5")).query))
        self.assertEqual(q["sni"], "t.example.com")
        self.assertNotIn("host", q)                       # grpc: no Host param

    def test_plain_http_link(self):
        link = "vless://id@p.example.com:8080?security=none&type=ws&path=%2F#p"
        self.assertEqual(scanner.link_target(link)[3:], (8080, False))
        q = dict(parse_qsl(urlsplit(scanner.rewrite_link(link, "104.16.9.9")).query))
        self.assertNotIn("sni", q)
        self.assertEqual(q["host"], "p.example.com")

    def test_vmess(self):
        link = vmess({"v": "2", "ps": "vm", "add": "v.example.com", "port": "443", "id": "x", "net": "ws",
                      "path": "/", "tls": "tls", "host": "", "sni": ""})
        self.assertEqual(scanner.link_target(link), ("vmess", "v.example.com", "v.example.com", 443, True))
        d = json.loads(base64.b64decode(scanner.rewrite_link(link, "104.17.0.1")[8:]))
        self.assertEqual((d["add"], d["sni"], d["host"], d["ps"]),
                         ("104.17.0.1", "v.example.com", "v.example.com", "vm-104.17.0.1"))

    def test_reality_is_refused(self):
        with self.assertRaises(SystemExit) as e:
            scanner.link_target("vless://id@1.2.3.4:443?security=reality&sni=www.example.com&pbk=k#r")
        self.assertIn("REALITY", str(e.exception))

    def test_ip_without_domain_is_refused(self):
        with self.assertRaises(SystemExit):
            scanner.link_target("vless://id@1.2.3.4:443?security=tls&type=ws#r")


class Candidates(unittest.TestCase):
    def test_spread_and_inside_ranges(self):
        nets, singles, skipped = scanner.load_ranges(None)
        self.assertEqual((len(nets), singles, skipped), (15, [], 0))
        ips = scanner.pick_candidates(nets, 500, random.Random(1))
        self.assertEqual(len(ips), 500)
        self.assertEqual(len({ip.rsplit(".", 1)[0] for ip in ips}), 500)          # one per /24
        for ip in ips:
            a = ipaddress.ip_address(ip)
            self.assertTrue(any(a in n for n in nets))
            self.assertNotIn(ip.rsplit(".", 1)[1], ("0", "255"))

    def test_file_with_ips_comments_and_v6(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# mine\n104.16.0.0/24\n172.64.1.1  # yesterday\n2606:4700::/32\nnot-an-ip\n")
        try:
            nets, singles, skipped = scanner.load_ranges(f.name)
        finally:
            os.unlink(f.name)
        self.assertEqual(([str(n) for n in nets], singles, skipped), (["104.16.0.0/24"], ["172.64.1.1"], 1))


class FakeEdge(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/cdn-cgi/trace":
            body = (b"fl=1\nh=%s\nip=127.0.0.1\nts=1\nvisit_scheme=https\ncolo=TST\nloc=IR\nwarp=off\n"
                    % self.headers["Host"].encode())
        elif self.path.startswith("/__down"):
            body = b"0" * int(self.path.split("=")[1])
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@unittest.skipUnless(shutil.which("openssl"), "needs openssl to make a test certificate")
class EndToEnd(unittest.TestCase):
    """A local TLS server that answers like a Cloudflare edge; the scanner runs as a user would run it."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        key, crt = os.path.join(cls.dir, "k.pem"), os.path.join(cls.dir, "c.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost", "-keyout", key, "-out", crt],
                       check=True, capture_output=True)
        cls.srv = HTTPServer(("127.0.0.1", 0), FakeEdge)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        cls.srv.socket = ctx.wrap_socket(cls.srv.socket, server_side=True)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        shutil.rmtree(cls.dir)

    def run_scanner(self, *args):
        script = os.path.join(os.path.dirname(__file__), "..", "scanner.py")
        return subprocess.run([sys.executable, script, *args], cwd=self.dir, capture_output=True, text=True, timeout=60)

    def test_scan_measure_speed_and_link(self):
        link = "vless://id@localhost:%d?security=tls&type=ws&path=%%2F#lab" % self.port
        r = self.run_scanner("--link", link, "--ip", "127.0.0.1", "--insecure", "--speed", "--speed-mb", "0.2",
                             "--speed-url", "https://localhost:%d/__down?bytes={bytes}" % self.port)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("working: 1 of 1", r.stdout)
        self.assertIn("TST", r.stdout)
        self.assertIn("Mbps", r.stdout)
        self.assertIn("vless://id@127.0.0.1:%d?" % self.port, r.stdout)
        with open(os.path.join(self.dir, "results.csv")) as f:
            self.assertEqual(f.read().splitlines()[1].split(",")[1:3], ["127.0.0.1", str(self.port)])

    def test_certificate_is_checked_by_default(self):
        r = self.run_scanner("-d", "localhost", "-p", str(self.port), "--ip", "127.0.0.1", "-o", "")
        self.assertEqual(r.returncode, 1)
        self.assertIn("bad-cert 1", r.stdout)

    def test_wrong_host_is_not_cloudflare(self):
        r = self.run_scanner("-d", "localhost", "-p", str(self.port), "--ip", "127.0.0.1", "--no-tls", "-o", "")
        self.assertEqual(r.returncode, 1)                   # plain http against a TLS port: no trace answer


if __name__ == "__main__":
    unittest.main()
