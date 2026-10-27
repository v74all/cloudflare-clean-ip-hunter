#!/usr/bin/env python3
"""cloudflare-clean-ip-hunter: find Cloudflare edge IPs that work well from your own network.

Run it with your VPN OFF, on the network you will actually use (mobile data, home wifi).
A clean IP is clean for your ISP at this time, not for everyone.

    python3 scanner.py -d your.domain.com        test with the domain of your own config
    python3 scanner.py --link 'vless://...'      take the domain from your link, print the link with the best IPs
    python3 scanner.py -d your.domain.com --speed   also measure download speed of the best ones

Standard library only, Python 3.8+ (Linux, macOS, Windows, Termux on Android).
"""
import argparse
import base64
import csv
import ipaddress
import json
import random
import re
import socket
import ssl
import statistics
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

VERSION = "2.1.0"

# https://www.cloudflare.com/ips-v4 (checked 2026-10-27)
CF_RANGES = """
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
""".split()

# ports Cloudflare proxies: https://developers.cloudflare.com/fundamentals/reference/network-ports/
TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
HTTP_PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095}
# transports whose share link carries a Host header that must stay your domain
HOST_TYPES = {"ws", "httpupgrade", "xhttp", "splithttp", "h2", "http"}
DEFAULT_DOMAIN = "speed.cloudflare.com"
DEFAULT_SPEED_URL = "https://speed.cloudflare.com/__down?bytes={bytes}"

REALITY_MSG = ("this is a REALITY link. REALITY talks to your server directly and can't go through Cloudflare,\n"
               "so a Cloudflare IP will never work for it. Clean IPs are only for configs behind the Cloudflare CDN\n"
               "(ws, xhttp, httpupgrade, grpc with tls, or the plain-http ports).")


class Target:
    """What every probe talks to: port, TLS on/off, SNI and Host header."""

    def __init__(self, sni, host, port, tls, insecure):
        self.sni, self.host, self.port, self.tls = sni, host, port, tls
        self.ctx = make_ctx(insecure)


def make_ctx(insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- links

def _vmess_decode(link):
    raw = link.split("://", 1)[1].strip()
    raw += "=" * (-len(raw) % 4)
    try:
        return json.loads(base64.b64decode(raw.replace("-", "+").replace("_", "/")).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise SystemExit("could not read the vmess link (not base64 json)") from None


def link_target(link):
    """(scheme, sni, host, port, tls) of a vless/trojan/vmess share link."""
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        d = _vmess_decode(link)
        if d.get("tls") == "reality":
            raise SystemExit(REALITY_MSG)
        add, port, tls = d.get("add", ""), int(d.get("port") or 443), d.get("tls") == "tls"
        sni = d.get("sni") or (d.get("host") or "").split(",")[0] or add
        host = (d.get("host") or "").split(",")[0] or sni
    elif scheme in ("vless", "trojan"):
        sp = urlsplit(link)
        q = dict(parse_qsl(sp.query, keep_blank_values=True))
        security = q.get("security") or ("tls" if scheme == "trojan" else "none")
        if security == "reality":
            raise SystemExit(REALITY_MSG)
        add, port, tls = sp.hostname or "", sp.port or 443, security == "tls"
        sni = q.get("sni") or q.get("host") or add
        host = q.get("host") or sni
    else:
        raise SystemExit("only vless://, trojan:// and vmess:// links can go through Cloudflare")
    if not sni or is_ip(sni):
        raise SystemExit("can't find your domain in the link: the address is an IP and there is no sni/host in it")
    return scheme, sni, host, port, tls


def rewrite_link(link, ip):
    """The same link with the address set to ip. SNI and Host are pinned to your domain first,
    otherwise the client would send the IP as SNI and Cloudflare would not know your site."""
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        d = _vmess_decode(link)
        add = d.get("add", "")
        if not is_ip(add):
            if d.get("tls") == "tls" and not d.get("sni"):
                d["sni"] = add
            if d.get("net") in HOST_TYPES and not d.get("host"):
                d["host"] = add
        d["add"] = ip
        d["ps"] = "%s-%s" % (d.get("ps") or "cf", ip)
        return "vmess://" + base64.b64encode(json.dumps(d, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).decode()
    sp = urlsplit(link)
    params = parse_qsl(sp.query, keep_blank_values=True)
    keys = {k for k, _ in params}
    q = dict(params)
    add = sp.hostname or ""
    extra = []
    if not is_ip(add):
        security = q.get("security") or ("tls" if scheme == "trojan" else "none")
        if security == "tls" and "sni" not in keys:
            extra.append(("sni", add))
        if q.get("type") in HOST_TYPES and "host" not in keys:
            extra.append(("host", add))
    query = sp.query + ("&" if sp.query and extra else "") + urlencode(extra)
    userinfo = sp.netloc.rsplit("@", 1)[0] + "@" if "@" in sp.netloc else ""
    name = quote("%s-%s" % (unquote(sp.fragment) or "cf", ip), safe="")
    return "%s://%s%s:%d%s#%s" % (scheme, userinfo, ip, sp.port or 443, "?" + query if query else "", name)


# ---------------------------------------------------------------- candidates

def load_ranges(path):
    """CIDRs and single IPs from a file (or the built-in Cloudflare list). IPv6 is skipped."""
    lines = CF_RANGES
    if path:
        with open(path, encoding="utf-8") as f:
            lines = [ln.split("#", 1)[0].strip() for ln in f]
    nets, singles, skipped = [], [], 0
    for item in filter(None, lines):
        try:
            if "/" in item:
                n = ipaddress.ip_network(item, strict=False)
                if n.version == 4:
                    nets.append(n)
                else:
                    skipped += 1
            else:
                a = ipaddress.ip_address(item)
                if a.version == 4:
                    singles.append(str(a))
                else:
                    skipped += 1
        except ValueError:
            print("skipping bad line: %s" % item, file=sys.stderr)
    return nets, singles, skipped


def pick_candidates(nets, count, rng):
    """count random IPs spread over the ranges: at most one per /24 until every /24 has been used."""
    if not nets or count <= 0:
        return []
    sizes = [max(1, n.num_addresses // 256) for n in nets]
    total = sum(sizes)
    out, seen = [], set()
    tries = 0
    while len(out) < count and tries < count * 50:
        tries += 1
        r, i = rng.randrange(total), 0
        while r >= sizes[i]:                        # which range: weighted by its number of /24 blocks
            r -= sizes[i]
            i += 1
        n = nets[i]
        if n.num_addresses < 256:
            ip = int(n.network_address) + rng.randrange(n.num_addresses)
        else:
            ip = int(n.network_address) + r * 256 + rng.randrange(1, 255)
        if (ip >> 8) in seen and len(seen) < total:
            continue
        seen.add(ip >> 8)
        out.append(str(ipaddress.IPv4Address(ip)))
    return out


# ---------------------------------------------------------------- probing

def http_get(ip, port, tls, sni, host, ctx, path, timeout, limit=8192):
    """One fresh connection. Returns (connect_ms, status, body)."""
    t0 = time.perf_counter()
    sock = socket.create_connection((ip, port), timeout=timeout)
    connect_ms = (time.perf_counter() - t0) * 1000
    try:
        if tls:
            sock = ctx.wrap_socket(sock, server_hostname=sni)
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
               "Connection: close\r\n\r\n" % (path, host))
        sock.sendall(req.encode("ascii"))
        data = b""
        while len(data) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    head, _, body = data.partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    return connect_ms, int(m.group(1)) if m else 0, body


def trace(ip, t, timeout):
    """One /cdn-cgi/trace request. ok only if Cloudflare itself answered for your domain."""
    try:
        ms, status, body = http_get(ip, t.port, t.tls, t.sni, t.host, t.ctx, "/cdn-cgi/trace", timeout)
    except socket.timeout:
        return {"ok": False, "why": "timeout"}
    except ConnectionResetError:
        return {"ok": False, "why": "reset"}
    except ConnectionRefusedError:
        return {"ok": False, "why": "refused"}
    except ssl.SSLCertVerificationError:
        return {"ok": False, "why": "bad-cert"}
    except ssl.SSLError:
        return {"ok": False, "why": "tls-error"}
    except OSError:
        return {"ok": False, "why": "net-error"}
    fields = dict(re.findall(r"^(\w+)=(.*)$", body.decode("ascii", "replace"), re.M))
    if status != 200 or "colo" not in fields:
        return {"ok": False, "why": "not-cloudflare" if status == 0 else "http-%d" % status}
    return {"ok": True, "ms": ms, "colo": fields.get("colo", "?"), "loc": fields.get("loc", "?"),
            "warp": fields.get("warp", "off")}


def measure(ip, first, t, timeout, rounds):
    """first = the trace that found the IP; rounds-1 more on fresh connections."""
    res = [first] + [trace(ip, t, timeout) for _ in range(rounds - 1)]
    ok = [r["ms"] for r in res if r["ok"]]
    if not ok:
        return None
    return {"ip": ip, "ping": statistics.median(ok), "jitter": statistics.pstdev(ok) if len(ok) > 1 else 0.0,
            "loss": 100.0 * (len(res) - len(ok)) / len(res), "colo": first["colo"], "speed": None}


def speed_test(ip, url, nbytes, timeout, insecure, max_seconds=10.0):
    """Download through ip. Returns Mbit/s, or None if it failed."""
    sp = urlsplit(url.replace("{bytes}", str(nbytes)))
    tls = sp.scheme == "https"
    port = sp.port or (443 if tls else 80)
    path = (sp.path or "/") + ("?" + sp.query if sp.query else "")
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if tls:
            sock = make_ctx(insecure).wrap_socket(sock, server_hostname=sp.hostname)
        sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                      % (path, sp.hostname)).encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(16384)
            if not chunk:
                return None
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        if not re.match(rb"HTTP/1\.[01] 200", head):
            return None
        got, t0 = len(body), time.perf_counter()
        while got < nbytes and time.perf_counter() - t0 < max_seconds:
            chunk = sock.recv(65536)
            if not chunk:
                break
            got += len(chunk)
        sock.close()
        dt = time.perf_counter() - t0
        return got * 8 / dt / 1e6 if dt > 0 and got > 65536 else None
    except (OSError, ssl.SSLError):
        return None


# ---------------------------------------------------------------- runner

def run_pool(func, items, workers, label, quiet=False):
    """func(item) over items with a progress line (erased at the end, so it leaves no row behind);
    Ctrl+C stops early and keeps what finished."""
    done, results, lock = [0], [], threading.Lock()
    tty = sys.stdout.isatty() and not quiet
    pool = ThreadPoolExecutor(max_workers=workers)
    futs = [pool.submit(func, it) for it in items]
    try:
        for f in as_completed(futs):
            r = f.result()
            with lock:
                done[0] += 1
                results.append(r)
                if tty:
                    good = sum(1 for x in results if x and x[1].get("ok", True))
                    sys.stdout.write("\r  %s %d/%d  ok %d " % (label, done[0], len(items), good))
                    sys.stdout.flush()
    except KeyboardInterrupt:
        print("\nstopped: keeping the results so far")
        for f in futs:
            f.cancel()
    finally:
        pool.shutdown(wait=False)
    if tty:
        sys.stdout.write("\r" + " " * 40 + "\r")
        sys.stdout.flush()
    return results


def parse_args():
    p = argparse.ArgumentParser(
        description="Find Cloudflare edge IPs that work well from your network (turn your VPN off first).")
    p.add_argument("-d", "--domain", help="domain of your own config behind Cloudflare (default: %s)" % DEFAULT_DOMAIN)
    p.add_argument("--link", help="your vless:// trojan:// or vmess:// link: domain, port and tls are taken from it, "
                                  "and the link is printed again with the best IPs")
    p.add_argument("-p", "--port", type=int, help="port (default 443, or the one in --link)")
    p.add_argument("--no-tls", action="store_true", help="plain http (ports 80, 8080, 8880, 2052, 2082, 2086, 2095)")
    p.add_argument("-n", "--count", type=int, default=200, help="random IPs to test (default 200)")
    p.add_argument("-r", "--ranges", help="file with CIDRs and/or single IPs (default: Cloudflare's official IPv4 list)")
    p.add_argument("--ip", action="append", default=[], help="test only this IP (repeatable)")
    p.add_argument("-w", "--workers", type=int, default=32, help="IPs tested at the same time (default 32)")
    p.add_argument("-t", "--timeout", type=float, default=2.5, help="seconds per step (default 2.5)")
    p.add_argument("--rounds", type=int, default=4, help="requests per working IP for ping/loss (default 4)")
    p.add_argument("--top", type=int, default=10, help="how many to show (default 10)")
    p.add_argument("--speed", action="store_true", help="download test on the best IPs (uses data: see --speed-mb)")
    p.add_argument("--speed-top", type=int, default=5, help="how many IPs get the download test (default 5)")
    p.add_argument("--speed-mb", type=float, default=5, help="MB per download test (default 5)")
    p.add_argument("--speed-url", default=DEFAULT_SPEED_URL, help="file to download through each IP")
    p.add_argument("--links", type=int, default=3, help="with --link: how many rewritten links (default 3)")
    p.add_argument("-o", "--output", default="results.csv", help="CSV file (default results.csv, '' = none)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="print only the result: the links with --link, else the best IPs one per line")
    p.add_argument("--insecure", action="store_true", help="don't verify the TLS certificate (not recommended)")
    p.add_argument("--seed", type=int, help="random seed (repeat the same sample)")
    p.add_argument("--version", action="version", version="cloudflare-clean-ip-hunter " + VERSION)
    a = p.parse_args()
    if a.count < 0 or a.workers < 1 or a.rounds < 1 or a.timeout <= 0:
        p.error("count, workers, rounds and timeout must be positive")
    return a


def main():
    a = parse_args()
    rng = random.Random(a.seed)
    scheme = None
    if a.link:
        scheme, sni, host, port, tls = link_target(a.link)
        if a.domain:
            sni = host = a.domain
    else:
        sni = host = a.domain or DEFAULT_DOMAIN
        port, tls = 443, True
    if a.port:
        port = a.port
    if a.no_tls:
        tls = False
    def say(*lines):
        if not a.quiet:
            print(*lines, sep="\n")

    if tls and port in HTTP_PORTS or not tls and port in TLS_PORTS:
        print("warning: %d is a %s port on Cloudflare" % (port, "plain-http" if port in HTTP_PORTS else "TLS"),
              file=sys.stderr)
    elif port not in TLS_PORTS | HTTP_PORTS:
        print("warning: Cloudflare doesn't proxy port %d" % port, file=sys.stderr)
    t = Target(sni, host, port, tls, a.insecure)

    if a.ip:
        cands = a.ip
    else:
        nets, singles, skipped = load_ranges(a.ranges)
        if skipped:
            print("note: %d IPv6 entries skipped (IPv4 only)" % skipped, file=sys.stderr)
        cands = singles + pick_candidates(nets, a.count, rng)
    if not cands:
        raise SystemExit("nothing to test")

    say("clean-ip-hunter %s: %d IPs, port %d, %s%s" % (VERSION, len(cands), port, "SNI " + sni if tls else "plain http",
                                                         "" if host == sni else ", Host " + host))
    if not a.domain and not a.link:
        say("tip: use your own config's domain: -d your.domain")

    first = run_pool(lambda ip: (ip, trace(ip, t, a.timeout)), cands, a.workers, "checked", a.quiet)
    good = [(ip, r) for ip, r in first if r["ok"]]
    why = Counter(r["why"] for _, r in first if not r["ok"])
    failed = " | " + ", ".join("%s %d" % kv for kv in why.most_common()) if why else ""
    if not good:
        print("working 0/%d%s" % (len(first), failed), file=sys.stderr if a.quiet else sys.stdout)
        if why.get("bad-cert"):
            print("certificate errors: is %s really behind Cloudflare\n(orange cloud)? check the domain" % sni)
        if why.get("timeout") or why.get("reset"):
            print("timeouts/resets on every IP: try -t 4, another network,\nor a plain-http port: --no-tls -p 8080")
        sys.exit(1)
    loc = Counter(r["loc"] for _, r in good).most_common(1)[0][0]
    say("working %d/%d, seen from %s%s" % (len(good), len(first), loc, failed))
    if loc != "IR" or any(r["warp"] != "off" for _, r in good):
        say("if you are in Iran, a VPN or WARP is still on: turn it",
            "off and scan again, or this says nothing about your ISP")

    rows = run_pool(lambda g: (g[0], measure(g[0], g[1], t, a.timeout, a.rounds) or {"ok": False}),
                    good, a.workers, "measured", a.quiet)
    rows = [r for _, r in rows if r.get("ok", True)]
    rows.sort(key=lambda r: (r["loss"], r["ping"], r["jitter"]))

    if a.speed and rows:
        nb = int(a.speed_mb * 1e6)
        run_pool(lambda r: (r, r.update(speed=speed_test(r["ip"], a.speed_url, nb, a.timeout, a.insecure)) or {}),
                 rows[:a.speed_top], 1, "speed test", a.quiet)
        if all(r["speed"] is None for r in rows[:a.speed_top]):
            say("download failed on all (speed host blocked? try --speed-url)")
        rows[:a.speed_top] = sorted(rows[:a.speed_top], key=lambda r: (r["loss"], -(r["speed"] or 0), r["ping"]))

    say(("%-3s%-16s%6s%6s%6s  %-5s%s" % ("#", "IP", "PING", "JIT", "LOSS", "COLO", "SPEED" if a.speed else "")).rstrip())
    for i, r in enumerate(rows[:a.top], 1):
        sp = ("%.1f Mbps" % r["speed"]) if r["speed"] else ("-" if a.speed else "")
        say(("%-3d%-16s%4.0fms%4.0fms%5.0f%%  %-5s%s" % (i, r["ip"], r["ping"], r["jitter"], r["loss"], r["colo"], sp)).rstrip())

    if a.output:
        with open(a.output, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["rank", "ip", "port", "ping_ms", "jitter_ms", "loss_pct", "colo", "speed_mbps"])
            for i, r in enumerate(rows, 1):
                w.writerow([i, r["ip"], port, round(r["ping"]), round(r["jitter"]), round(r["loss"]), r["colo"],
                            round(r["speed"], 1) if r["speed"] else ""])
        say("all %d working IPs -> %s" % (len(rows), a.output))

    if a.link and rows:
        links = [rewrite_link(a.link, r["ip"]) for r in rows[:a.links]]
        with open("links.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(links) + "\n")
        say("your %s link with the best IPs -> links.txt" % scheme, "(address = the IP, SNI and Host stay %s)" % sni)
        print("\n".join(links))
    elif a.quiet:
        print("\n".join(r["ip"] for r in rows[:a.top]))


if __name__ == "__main__":
    main()
