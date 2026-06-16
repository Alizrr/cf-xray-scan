import argparse
import base64
import copy
import csv
import ipaddress
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote, quote

import xray_test as xt

DEFAULT_CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

_lock = threading.Lock()
_port_counter = [0]


def log(msg):
    with _lock:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()


def expand_ips(cidrs, sample, ip_file):
    ips = []
    if ip_file:
        with open(ip_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip().lstrip("﻿")
                if not line or line.startswith("#"):
                    continue
                try:
                    if "/" in line:
                        ips.extend(str(i) for i in ipaddress.ip_network(line, strict=False).hosts())
                    else:
                        ips.append(str(ipaddress.ip_address(line)))
                except ValueError:
                    pass
    else:
        for c in cidrs:
            net = ipaddress.ip_network(c, strict=False)
            if net.num_addresses > 65536 and sample:
                first, last = int(net.network_address) + 1, int(net.broadcast_address) - 1
                seen = set()
                tries = 0
                while len(seen) < sample and tries < sample * 6:
                    seen.add(random.randint(first, last))
                    tries += 1
                ips.extend(str(ipaddress.ip_address(n)) for n in seen)
            else:
                ips.extend(str(i) for i in net.hosts())
    ips = list(dict.fromkeys(ips))
    if sample and len(ips) > sample:
        ips = random.sample(ips, sample)
    random.shuffle(ips)
    return ips


def rebuild_link(link, ip):
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()
    u = urlparse(link)
    base_tag = unquote(u.fragment) if u.fragment else "config"
    new_tag = quote(f"{base_tag}-{ip}")

    if scheme in ("vless", "trojan"):
        old = f"@{u.hostname}:"
        new = f"@{ip}:"
        body, _, _frag = link.partition("#")
        body = body.replace(old, new, 1)
        return f"{body}#{new_tag}"

    if scheme == "vmess":
        raw = link.split("://", 1)[1].split("#", 1)[0]
        raw += "=" * (-len(raw) % 4)
        cfg = json.loads(base64.b64decode(raw).decode("utf-8"))
        cfg["add"] = ip
        cfg["ps"] = f"{cfg.get('ps', 'config')}-{ip}"
        enc = base64.b64encode(json.dumps(cfg, ensure_ascii=False).encode("utf-8")).decode()
        return "vmess://" + enc

    return link


def set_address(outbound, ip):
    ob = copy.deepcopy(outbound)
    s = ob["settings"]
    if "vnext" in s:
        s["vnext"][0]["address"] = ip
    elif "servers" in s:
        s["servers"][0]["address"] = ip
    return ob


def scan_one(ip, outbound, base_port, xray, upload_mb, ready_timeout, test_timeout):
    res = {"ip": ip, "upload_mbps": None, "ping_ms": None, "ok": False, "error": None}
    with _lock:
        _port_counter[0] += 1
        port = base_port + _port_counter[0]

    cfg = xt.build_config(set_address(outbound, ip), port)
    fd, cfg_path = tempfile.mkstemp(suffix=".json", prefix=f"xs_{port}_")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    proc = None
    try:
        proc = subprocess.Popen([xray, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        opener = xt.make_opener(port)
        try:
            xt.wait_ready(opener, timeout=ready_timeout)
        except Exception:
            res["error"] = "tunnel did not come up"
            return res

        ping = xt.test_ping(opener, count=2)
        if ping:
            res["ping_ms"] = ping["avg"]
        ul = xt.test_upload(opener, upload_mb, test_timeout)
        if "error" in ul:
            res["error"] = "upload failed"
        else:
            res["upload_mbps"] = ul["mbps"]
            res["ok"] = True
    except Exception as e:
        res["error"] = f"{type(e).__name__}"
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=4)
            except Exception:
                proc.kill()
        try:
            os.remove(cfg_path)
        except OSError:
            pass
    return res


def main():
    p = argparse.ArgumentParser(
        description="Scan a Cloudflare IP range for the best upload speed of your config")
    p.add_argument("link", help="Config link (vless/vmess/trojan)")
    p.add_argument("--cidr", action="append", default=[], help="CIDR range (repeatable)")
    p.add_argument("--ip-file", help="File with a list of IPs/CIDRs")
    p.add_argument("--xray", help="Path to xray.exe")
    p.add_argument("--sample", type=int, default=60, help="Number of IPs to test (random sample)")
    p.add_argument("--concurrency", type=int, default=8, help="Number of concurrent tunnels")
    p.add_argument("--base-port", type=int, default=20000, help="Starting local port")
    p.add_argument("--upload-mb", type=int, default=4, help="Upload test size per IP (MB)")
    p.add_argument("--ready-timeout", type=float, default=6.0, help="Tunnel start timeout (s)")
    p.add_argument("--test-timeout", type=float, default=12.0, help="Upload test timeout (s)")
    p.add_argument("--top", type=int, default=15)
    p.add_argument("--out", default="cf_xray_results.csv")
    p.add_argument("--links-out", default="best_configs.txt",
                   help="Output file for ready-to-use links with the best IPs")
    p.add_argument("--make-links", type=int, default=5,
                   help="How many top IPs to build ready-to-use links for")
    args = p.parse_args()

    xray = xt.find_xray(args.xray)
    if not xray:
        log("ERROR: xray not found. Pass its path with --xray (e.g. inside v2rayN/bin/xray).")
        sys.exit(2)

    outbound, host, port = xt.parse_link(args.link)
    ss = outbound["streamSettings"]
    sni = ss.get("tlsSettings", ss.get("realitySettings", {})).get("serverName")
    log(f"OK xray: {xray}")
    log(f"OK config: SNI={sni}  network={ss.get('network')}  "
        f"path={ss.get('wsSettings', {}).get('path', '-')}")

    cidrs = args.cidr if (args.cidr or args.ip_file) else DEFAULT_CF_RANGES
    ips = expand_ips(cidrs, args.sample, args.ip_file)
    log(f"OK {len(ips)} IPs to test, {args.concurrency} concurrent tunnels, "
        f"{args.upload_mb}MB upload each.\n")

    results = []
    done = 0
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = {ex.submit(scan_one, ip, outbound, args.base_port, xray,
                          args.upload_mb, args.ready_timeout, args.test_timeout): ip for ip in ips}
        for fut in as_completed(futs):
            r = fut.result()
            done += 1
            if r["ok"]:
                results.append(r)
                log(f"  [{done}/{len(ips)}] OK  {r['ip']:<16} up {r['upload_mbps']:>7} Mbps  "
                    f"ping {r['ping_ms']}ms")
            else:
                log(f"  [{done}/{len(ips)}] --  {r['ip']:<16} ({r['error']})")

    results.sort(key=lambda x: x["upload_mbps"], reverse=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ip", "upload_mbps", "ping_ms"])
        w.writeheader()
        for r in results:
            w.writerow({k: r[k] for k in ("ip", "upload_mbps", "ping_ms")})

    el = time.perf_counter() - t0
    log("\n" + "=" * 56)
    log(f"[*] Done. {done} IPs in {el:.0f}s, {len(results)} working IPs.")
    log(f"[*] Output: {args.out}\n")
    log(f"=== Top {min(args.top, len(results))} IPs for this config's upload ===")
    log(f"{'#':>3}  {'IP':<16}  {'Upload(Mbps)':>12}  {'Ping(ms)':>8}")
    for i, r in enumerate(results[:args.top], 1):
        log(f"{i:>3}  {r['ip']:<16}  {r['upload_mbps']:>12}  {str(r['ping_ms']):>8}")

    if not results:
        log("No working IP found - either this domain is not actually proxied through")
        log("Cloudflare, or the SNI/path is wrong. (A direct origin can't be hit via a CF IP.)")
        return

    n_links = min(args.make_links, len(results))
    links = [rebuild_link(args.link, r["ip"]) for r in results[:n_links]]
    with open(args.links_out, "w", encoding="utf-8") as f:
        f.write("\n".join(links) + "\n")
    log(f"\n=== {n_links} ready-to-use links (IP substituted) - also saved to {args.links_out} ===")
    log("You can copy all of this and add it in v2rayN via 'Add configs from clipboard':\n")
    for r, lk in zip(results[:n_links], links):
        log(f"# up {r['upload_mbps']} Mbps  ping {r['ping_ms']}ms")
        log(lk + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n[!] Stopped.")
        sys.exit(130)
