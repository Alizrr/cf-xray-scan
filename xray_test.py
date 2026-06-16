import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse, parse_qs, unquote


def parse_link(link):
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vless":
        return parse_vless(link)
    if scheme == "trojan":
        return parse_trojan(link)
    if scheme == "vmess":
        return parse_vmess(link)
    raise ValueError(f"Unsupported protocol: {scheme} (only vless/vmess/trojan)")


def _common_stream(q, host):
    net = (q.get("type", ["tcp"])[0]).lower()
    security = (q.get("security", ["none"])[0]).lower()
    sni = q.get("sni", [q.get("host", [host])[0]])[0]
    host_hdr = q.get("host", [sni])[0]
    path = unquote(q.get("path", ["/"])[0])
    fp = q.get("fp", ["chrome"])[0]
    alpn = q.get("alpn", [""])[0]
    alpn_list = [a for a in unquote(alpn).split(",") if a] or ["h2", "http/1.1"]

    stream = {"network": net}
    if security in ("tls", "reality"):
        stream["security"] = security
        tls = {"serverName": sni, "fingerprint": fp, "allowInsecure": False, "alpn": alpn_list}
        if security == "reality":
            tls = {
                "serverName": sni, "fingerprint": fp,
                "publicKey": q.get("pbk", [""])[0],
                "shortId": q.get("sid", [""])[0],
                "spiderX": q.get("spx", ["/"])[0],
            }
            stream["realitySettings"] = tls
        else:
            stream["tlsSettings"] = tls
    else:
        stream["security"] = "none"

    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_hdr}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": unquote(q.get("serviceName", [""])[0])}
    elif net in ("tcp", "raw") and q.get("headerType", [""])[0] == "http":
        stream["tcpSettings"] = {"header": {"type": "http",
                                            "request": {"headers": {"Host": [host_hdr]}}}}
    return stream


def parse_vless(link):
    u = urlparse(link)
    q = parse_qs(u.query)
    out = {
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": u.hostname, "port": u.port or 443,
            "users": [{"id": u.username, "encryption": q.get("encryption", ["none"])[0],
                       "flow": q.get("flow", [""])[0]}],
        }]},
        "streamSettings": _common_stream(q, u.hostname),
    }
    if not out["settings"]["vnext"][0]["users"][0]["flow"]:
        del out["settings"]["vnext"][0]["users"][0]["flow"]
    return out, u.hostname, u.port or 443


def parse_trojan(link):
    u = urlparse(link)
    q = parse_qs(u.query)
    out = {
        "protocol": "trojan",
        "settings": {"servers": [{"address": u.hostname, "port": u.port or 443,
                                  "password": u.username}]},
        "streamSettings": _common_stream(q, u.hostname),
    }
    return out, u.hostname, u.port or 443


def parse_vmess(link):
    raw = link.split("://", 1)[1]
    raw += "=" * (-len(raw) % 4)
    cfg = json.loads(base64.b64decode(raw).decode("utf-8"))
    host = cfg.get("add")
    port = int(cfg.get("port", 443))
    q = {
        "type": [cfg.get("net", "tcp")], "security": [cfg.get("tls", "none") or "none"],
        "sni": [cfg.get("sni") or cfg.get("host") or host],
        "host": [cfg.get("host") or host], "path": [cfg.get("path", "/")],
        "headerType": [cfg.get("type", "")],
    }
    out = {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port,
                               "users": [{"id": cfg.get("id"),
                                          "alterId": int(cfg.get("aid", 0)),
                                          "security": cfg.get("scy", "auto")}]}]},
        "streamSettings": _common_stream({k: v for k, v in q.items()}, host),
    }
    return out, host, port


def build_config(outbound, http_port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "http-in", "listen": "127.0.0.1", "port": http_port,
            "protocol": "http", "settings": {"allowTransparent": False},
        }],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }


def find_xray(user_path):
    candidates = []
    if user_path:
        candidates.append(user_path)
    here = os.path.dirname(os.path.abspath(__file__))
    names = ["xray.exe", "xray", "v2ray.exe", "v2ray"]
    candidates += [os.path.join(here, n) for n in names]
    candidates += names
    for c in candidates:
        if os.path.isabs(c) and os.path.isfile(c):
            return c
        if not os.path.isabs(c):
            from shutil import which
            w = which(c)
            if w:
                return w
    return None


def make_opener(http_port):
    proxy = f"http://127.0.0.1:{http_port}"
    handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    return urllib.request.build_opener(handler)


def wait_ready(opener, timeout=15):
    test_url = "https://www.gstatic.com/generate_204"
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            req = urllib.request.Request(test_url, headers={"User-Agent": "xray-test"})
            with opener.open(req, timeout=6) as r:
                if r.status in (204, 200):
                    return True
        except Exception as e:
            last = e
        time.sleep(0.5)
    raise RuntimeError(f"tunnel not ready: {last}")


def test_ping(opener, count=5):
    url = "https://www.gstatic.com/generate_204"
    samples = []
    for _ in range(count):
        try:
            t = time.perf_counter()
            req = urllib.request.Request(url, headers={"User-Agent": "xray-test"})
            with opener.open(req, timeout=8) as r:
                r.read()
            samples.append((time.perf_counter() - t) * 1000)
        except Exception:
            pass
        time.sleep(0.2)
    if not samples:
        return None
    samples.sort()
    return {"min": round(min(samples), 1), "avg": round(sum(samples) / len(samples), 1),
            "max": round(max(samples), 1), "loss": round(100 * (count - len(samples)) / count)}


def test_download(opener, mb, timeout):
    n = mb * 1024 * 1024
    url = f"https://speed.cloudflare.com/__down?bytes={n}"
    t = time.perf_counter()
    got = 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "xray-test"})
        with opener.open(req, timeout=timeout) as r:
            while True:
                chunk = r.read(256 * 1024)
                if not chunk:
                    break
                got += len(chunk)
                if time.perf_counter() - t > timeout:
                    break
    except Exception as e:
        if got == 0:
            return {"error": f"{type(e).__name__}: {e}"}
    el = time.perf_counter() - t
    return {"mbps": round(got * 8 / el / 1_000_000, 2), "mb": round(got / 1024 / 1024, 1),
            "sec": round(el, 1)}


def test_upload(opener, mb, timeout):
    n = mb * 1024 * 1024
    payload = os.urandom(n)
    url = "https://speed.cloudflare.com/__up"
    t = time.perf_counter()
    try:
        req = urllib.request.Request(url, data=payload, method="POST",
                                     headers={"User-Agent": "xray-test",
                                              "Content-Type": "application/octet-stream"})
        with opener.open(req, timeout=timeout) as r:
            r.read()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    el = time.perf_counter() - t
    return {"mbps": round(n * 8 / el / 1_000_000, 2), "mb": round(n / 1024 / 1024, 1),
            "sec": round(el, 1)}


def main():
    p = argparse.ArgumentParser(description="Real speed test of a config from inside the xray tunnel")
    p.add_argument("link", nargs="?", help="Config link (vless/vmess/trojan)")
    p.add_argument("--link-file", help="File with links (one config per line)")
    p.add_argument("--xray", help="Path to the xray executable (default: next to script or PATH)")
    p.add_argument("--port", type=int, default=10809, help="Local HTTP proxy port")
    p.add_argument("--download-mb", type=int, default=20, help="Download test size (MB)")
    p.add_argument("--upload-mb", type=int, default=10, help="Upload test size (MB)")
    p.add_argument("--duration", type=int, default=15, help="Max time per test (s)")
    p.add_argument("--keep-config", action="store_true", help="Do not delete the temp config file")
    args = p.parse_args()

    links = []
    if args.link:
        links.append(args.link)
    if args.link_file:
        with open(args.link_file, encoding="utf-8") as f:
            links += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not links:
        p.error("give a config link, or --link-file")

    xray = find_xray(args.xray)
    if not xray:
        print("ERROR: xray executable not found. Download it and put xray.exe next to this script:")
        print("   https://github.com/XTLS/Xray-core/releases")
        print("   or pass its path with --xray.")
        sys.exit(2)
    print(f"OK xray: {xray}\n")

    for idx, link in enumerate(links, 1):
        tag = link.split("#", 1)[1] if "#" in link else f"config-{idx}"
        print("=" * 60)
        print(f"[{idx}/{len(links)}] {unquote(tag)}")
        print("=" * 60)
        try:
            outbound, host, port = parse_link(link)
        except Exception as e:
            print(f"  ERROR parsing link: {e}\n")
            continue
        print(f"  server: {host}:{port}   network: {outbound['streamSettings'].get('network')}"
              f"   security: {outbound['streamSettings'].get('security')}")

        cfg = build_config(outbound, args.port)
        fd, cfg_path = tempfile.mkstemp(suffix=".json", prefix="xray_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)

        proc = None
        try:
            proc = subprocess.Popen(
                [xray, "run", "-c", cfg_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            opener = make_opener(args.port)
            print("  connecting tunnel...", end=" ", flush=True)
            try:
                wait_ready(opener, timeout=15)
                print("connected OK")
            except Exception as e:
                print(f"FAILED  ({e})")
                out = proc.stdout.read() if proc.stdout else ""
                if out.strip():
                    print("  --- xray output ---")
                    print("  " + out.strip().replace("\n", "\n  "))
                continue

            ping = test_ping(opener)
            if ping:
                print(f"  ping: avg {ping['avg']}ms  (min {ping['min']} / max {ping['max']}"
                      f" / loss {ping['loss']}%)")
            else:
                print("  ping: failed")

            dl = test_download(opener, args.download_mb, args.duration)
            if "error" in dl:
                print(f"  download: failed ({dl['error']})")
            else:
                print(f"  download: {dl['mbps']} Mbps   ({dl['mb']}MB in {dl['sec']}s)")

            ul = test_upload(opener, args.upload_mb, args.duration)
            if "error" in ul:
                print(f"  upload: failed ({ul['error']})")
            else:
                print(f"  upload: {ul['mbps']} Mbps   ({ul['mb']}MB in {ul['sec']}s)")
            print()
        finally:
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
            if not args.keep_config:
                try:
                    os.remove(cfg_path)
                except OSError:
                    pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
        sys.exit(130)
