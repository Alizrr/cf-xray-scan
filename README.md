# cf-xray-scan

Find the Cloudflare edge IP that gives *your* proxy config the best upload speed.

If you run a VLESS / VMess / Trojan config behind Cloudflare, the domain in your
config can be reached through any Cloudflare IP — but from where you sit, some of
those IPs are fast and most are slow or dead. The usual "clean IP" scanners only
ping the edge or test a generic Cloudflare endpoint. This one is different: for
every IP it actually brings up **your** config's tunnel through that IP and measures
the real upload speed inside it. So the numbers you get are the numbers you'll
actually have when you connect.

> Read this in Persian: [README.fa.md](README.fa.md)

## Why I made it

Most scanners answer "which Cloudflare IP is fast in general?". The question I
actually care about is "which IP is fast *for my config, from my line, right now?*"
— and those two aren't the same thing. Upload especially: a lot of IPs that look
fine on download choke on upload. So the tool dials each IP through xray with your
real SNI/host/path and pushes a few MB up through it. No guessing.

## Requirements

- Python 3.8+ (standard library only — nothing to `pip install`)
- The `xray` binary. If you have v2rayN, it's already there, e.g.
  `...\v2rayN-windows-64\bin\xray\xray.exe`. Otherwise grab it from
  [Xray-core releases](https://github.com/XTLS/Xray-core/releases).
- `xray_test.py` must sit next to `cf_xray_scan.py` (the scanner imports it).

## Usage

Basic run (default Cloudflare ranges, 60 sampled IPs):

```powershell
python cf_xray_scan.py "<your config link>" --xray "C:\path\to\xray.exe"
```

A more thorough scan on the ranges that tend to be good:

```powershell
python cf_xray_scan.py "<your config link>" `
  --xray "C:\path\to\xray.exe" `
  --cidr 104.16.0.0/13 --cidr 172.64.0.0/13 `
  --sample 100 --concurrency 6 --ready-timeout 12
```

From your own IP list (one IP or CIDR per line):

```powershell
python cf_xray_scan.py "<your config link>" --xray "C:\path\to\xray.exe" --ip-file ips.txt
```

Keep the config link inside quotes — it contains `&`, which the shell will
otherwise eat.

## What you get

- a sorted table of the best IPs (upload + ping) in the terminal
- `cf_xray_results.csv` — the full results
- `best_configs.txt` — ready-to-paste config links with the winning IP already
  swapped in. Copy the whole file and import it in v2rayN via
  *Add configs from clipboard*.

Then just point your client at the best IP (or import `best_configs.txt`) and the
SNI / host / path stay exactly as they were.

## Options

| Flag | What it does | Default |
|------|--------------|---------|
| `--cidr` | a CIDR range, repeatable | official Cloudflare ranges |
| `--ip-file` | file with IPs / CIDRs | — |
| `--xray` | path to the xray binary | next to script / on PATH |
| `--sample` | how many IPs to test | 60 |
| `--concurrency` | tunnels running at once | 8 |
| `--upload-mb` | upload size per IP, in MB | 4 |
| `--ready-timeout` | how long to wait for a tunnel | 6s |
| `--make-links` | how many top IPs to turn into links | 5 |
| `--top` | how many rows to print | 15 |

There's a smaller companion script too — `xray_test.py "<link>" --xray ...` — which
just connects one config and reports ping / download / upload. Handy for a quick
"is this config even alive?" check.

## A few honest notes

- High pings (900ms+) and a low upload ceiling are usually the route or the origin
  server, not the scanner. The tool measures reality; it can't beat it.
- If you see a lot of `tunnel did not come up`, raise `--ready-timeout` to 10–15 and
  drop `--concurrency` — when latency is high, too many tunnels at once just step on
  each other.
- This only makes sense if the config is genuinely behind Cloudflare. If the domain
  resolves straight to the origin, no Cloudflare IP will route to it and you'll get
  zero working IPs (which is itself useful information).

## License

MIT — see [LICENSE](LICENSE).
