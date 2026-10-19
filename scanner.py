import argparse
import ipaddress
import random
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor

def parse_args():
    parser = argparse.ArgumentParser(description="Cloudflare Clean IP Prober & Latency Benchmarker")
    parser.add_argument("-c", "--cidr", default="cidr_ranges.txt")
    parser.add_argument("-s", "--samples", type=int, default=12)
    parser.add_argument("-w", "--workers", type=int, default=32)
    parser.add_argument("-t", "--timeout", type=float, default=1.5)
    parser.add_argument("-o", "--output", default="clean_ips.txt")
    parser.add_argument("--sni", default="cloudflare.com")
    parser.add_argument("--port", type=int, default=443)
    return parser.parse_args()

def load_candidate_ips(cidr_file, samples_per_subnet):
    candidates = []
    try:
        with open(cidr_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        lines = [
            "104.16.0.0/13",
            "104.24.0.0/14",
            "172.64.0.0/13",
            "162.158.0.0/15",
            "198.41.128.0/17",
            "188.114.96.0/20"
        ]
    for block in lines:
        try:
            net = ipaddress.ip_network(block)
            total = net.num_addresses
            count = min(samples_per_subnet, max(1, total - 4))
            chosen = set()
            while len(chosen) < count:
                idx = random.randint(2, total - 3)
                chosen.add(str(net[idx]))
            candidates.extend(chosen)
        except ValueError:
            continue
    random.shuffle(candidates)
    return candidates

def probe_endpoint(ip, port, sni, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t0 = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=sni) as ss:
                rtt = (time.perf_counter() - t0) * 1000.0
                return ip, round(rtt, 2), True
    except Exception:
        return ip, 99999.0, False

def main():
    args = parse_args()
    print(f"[*] Target SNI: {args.sni}:{args.port}")
    candidates = load_candidate_ips(args.cidr, args.samples)
    print(f"[*] Probing {len(candidates)} candidate IPs using {args.workers} concurrent workers...")

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(probe_endpoint, ip, args.port, args.sni, args.timeout) for ip in candidates]
        for f in futures:
            ip, rtt, success = f.result()
            if success:
                results.append((ip, rtt))
                print(f"[+] FOUND: {ip:<18} RTT: {rtt:>6.2f} ms")

    results.sort(key=lambda x: x[1])
    print(f"\n[*] Scan Complete. Clean nodes discovered: {len(results)}")
    print("-" * 42)
    print(f"{'RANK':<6}{'CLEAN IP':<18}{'LATENCY':<12}")
    print("-" * 42)
    for i, (ip, rtt) in enumerate(results[:15], 1):
        print(f"#{i:<5}{ip:<18}{rtt:>6.2f} ms")

    if args.output and results:
        with open(args.output, "w", encoding="utf-8") as f:
            for ip, rtt in results:
                f.write(f"{ip}\t{rtt}ms\n")
        print(f"\n[*] Top clean IPs saved to: {args.output}")

if __name__ == "__main__":
    main()
