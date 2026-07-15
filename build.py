#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Generate 4 Shadowrocket configs: {global,china} x {public-dns,home-dns}.

All rules are inlined from MetaCubeX/meta-rules-dat (meta branch) -- zero
runtime external links. Re-run to refresh rule data, then re-import the conf.
"""

import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

# ---- macros (edit here) -----------------------------------------------------
INTERNAL_PROXY_CIDRS = ["192.168.8.0/24", "192.168.18.0/24", "192.168.28.0/24"]
INTERNAL_DNS = "192.168.8.2"

# ---- rule data sources (meta-rules-dat, meta branch) -------------------------
BASE = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo"
# big companies直连 (china config): geosite for all; geoip only where meta-rules-dat has it
BIGCO = ["apple", "amazon", "microsoft", "akamai", "fastly", "google",
         "cloudflare", "netflix", "telegram", "twitter", "facebook"]
GEOIP = ["cn", "fastly", "google", "cloudflare", "netflix", "telegram", "twitter", "facebook"]
SOURCES = (
    {f"geosite-{c}": f"{BASE}/geosite/{c}.list" for c in ["cn", "gfw", *BIGCO]}
    | {"geosite-ai": f"{BASE}/geosite/category-ai-%21cn.list"}
    | {f"geoip-{c}": f"{BASE}/geoip/{c}.list" for c in GEOIP}
)

ROOT = Path(__file__).parent
CACHE = ROOT / ".cache"
DIST = ROOT / "dist"

PRIVATE_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8", "192.168.0.0/16"]

GENERAL = """\
bypass-system = true
skip-proxy = 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32
ipv6 = false
private-ip-answer = true
icmp-auto-reply = true
dns-direct-fallback-proxy = false
udp-policy-not-supported-behaviour = REJECT
always-reject-url-rewrite = false
use-local-host-item-for-proxy = false"""

# DoH by hostname only (IP-literal DoH not usable); [Host] pins bootstrap the
# hostnames for locally-resolved (non-#proxy) DoH. #proxy DoH hostnames resolve
# remotely on the proxy side, no pin needed there.
DNS_PUB_GLOBAL = """\
dns-server = https://cloudflare-dns.com/dns-query#proxy, https://dns.google/dns-query#proxy
fallback-dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
proxy-dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
dns-direct-system = true"""

DNS_PUB_CHINA = """\
dns-server = https://cloudflare-dns.com/dns-query, https://dns.google/dns-query
fallback-dns-server = system
proxy-dns-server = https://cloudflare-dns.com/dns-query
dns-direct-system = true"""

# home-dns always rides the proxy back home (single path, no at-home special case).
# proxy-dns-server bootstraps the node hostname itself (must NOT loop through #proxy):
# global (in CN) -> alidns + doh.pub; china (abroad) -> cloudflare
DNS_HOME_GLOBAL = f"""\
dns-server = {INTERNAL_DNS}#proxy
fallback-dns-server = system
proxy-dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
dns-direct-system = false"""

DNS_HOME_CHINA = f"""\
dns-server = {INTERNAL_DNS}#proxy
fallback-dns-server = system
proxy-dns-server = https://cloudflare-dns.com/dns-query
dns-direct-system = false"""

HOSTS_CN = """\
[Host]
dns.alidns.com = 223.5.5.5
doh.pub = 1.12.12.12"""

HOSTS_ABROAD = """\
[Host]
cloudflare-dns.com = 1.1.1.1
dns.google = 8.8.4.4"""

URL_REWRITE_GLOBAL = """\
[URL Rewrite]
^https?://(www.)?g.cn($|/.*) https://www.google.com$2 302
^https?://(www.)?google.cn($|/.*) https://www.google.com$2 302"""


def fetch(name: str, url: str) -> str:
    CACHE.mkdir(exist_ok=True)
    cached = CACHE / f"{name}.list"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            text = r.read().decode()
        cached.write_text(text)
        return text
    except OSError as e:
        if cached.exists():
            print(f"WARN: fetch {name} failed ({e}), using cached copy", file=sys.stderr)
            return cached.read_text()
        raise


def domain_rules(text: str, policy: str) -> list[str]:
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("+."):
            out.append(f"DOMAIN-SUFFIX,{ln[2:]},{policy}")
        elif re.fullmatch(r"[\w.-]+", ln):
            out.append(f"DOMAIN,{ln},{policy}")
        else:
            print(f"WARN: skip unrecognized domain line: {ln}", file=sys.stderr)
    return out


def ip_rules(cidrs, policy: str, no_resolve: bool = True) -> list[str]:
    tail = ",no-resolve" if no_resolve else ""
    out = []
    for ln in cidrs:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if "/" in ln and re.fullmatch(r"[0-9a-fA-F.:]+/\d+", ln):
            out.append(f"IP-CIDR,{ln},{policy}{tail}")
        else:
            print(f"WARN: skip unrecognized cidr line: {ln}", file=sys.stderr)
    return out


def render_blocks(blocks: list[tuple[str, list[str]]]) -> list[str]:
    """TOC of all block headers up front, then each block repeats its header."""
    out = ["# " + "=" * 24 + " blocks " + "=" * 24]
    out += [f"# {i}. {desc}" for i, (desc, _) in enumerate(blocks, 1)]
    out.append("# " + "=" * 56)
    for i, (desc, lines) in enumerate(blocks, 1):
        out += ["", f"# ----- {i}. {desc} -----", *lines]
    return out


def main() -> None:
    # any fetch failure raises -> non-zero exit -> CI stops before commit/push
    data = {name: fetch(name, url) for name, url in SOURCES.items()}

    # per-company: geosite + geoip (where available) together
    bigco_lines = []
    for c in BIGCO:
        bigco_lines.append(f"# {c}")
        bigco_lines += domain_rules(data[f"geosite-{c}"], "DIRECT")
        if f"geoip-{c}" in data:
            bigco_lines += ip_rules(data[f"geoip-{c}"].splitlines(), "DIRECT")

    lan_block = (
        f"lan: internal CIDRs {' '.join(INTERNAL_PROXY_CIDRS)} -> PROXY (macro); other private -> DIRECT",
        [*ip_rules(INTERNAL_PROXY_CIDRS, "PROXY"), *ip_rules(PRIVATE_CIDRS, "DIRECT")],
    )

    # global: only definitely-CN goes direct, everything else proxy
    global_rules = render_blocks([
        lan_block,
        ("cn: geosite cn + geoip cn -> DIRECT",
         [*domain_rules(data["geosite-cn"], "DIRECT"),
          *ip_rules(data["geoip-cn"].splitlines(), "DIRECT")]),
        ("final -> PROXY", ["FINAL,PROXY"]),
    ])

    # china: AI/gfwlist/big-co direct, CN domains+IPs proxy, rest direct
    china_rules = render_blocks([
        lan_block,
        ("ai: category-ai-!cn -> DIRECT", domain_rules(data["geosite-ai"], "DIRECT")),
        ("gfw: gfwlist -> DIRECT", domain_rules(data["geosite-gfw"], "DIRECT")),
        (f"bigco: geosite+geoip -> DIRECT ({' '.join(BIGCO)})", bigco_lines),
        ("cn: geosite cn + geoip cn -> PROXY (geoip without no-resolve: missed CN domains match by IP)",
         [*domain_rules(data["geosite-cn"], "PROXY"),
          *ip_rules(data["geoip-cn"].splitlines(), "PROXY", no_resolve=False)]),
        ("final -> DIRECT", ["FINAL,DIRECT"]),
    ])

    variants = {
        "global-public-dns": (DNS_PUB_GLOBAL, global_rules, HOSTS_CN, URL_REWRITE_GLOBAL),
        "global-home-dns": (DNS_HOME_GLOBAL, global_rules, HOSTS_CN, URL_REWRITE_GLOBAL),
        "china-public-dns": (DNS_PUB_CHINA, china_rules, HOSTS_ABROAD, ""),
        "china-home-dns": (DNS_HOME_CHINA, china_rules, HOSTS_ABROAD, ""),
    }

    DIST.mkdir(exist_ok=True)
    for name, (dns, rules, hosts, extra) in variants.items():
        assert rules[-1].startswith("FINAL,")
        body = "\n".join(
            [f"# {name}.conf generated by build.py on {date.today()}",
             "# rules inlined from MetaCubeX/meta-rules-dat (meta branch)",
             "[General]", GENERAL, dns, "", hosts, "", "[Rule]", *rules]
        )
        if extra:
            body += f"\n\n{extra}"
        out = DIST / f"{name}.conf"
        out.write_text(body + "\n")
        n_rules = sum(1 for r in rules if r and not r.startswith("#"))
        print(f"{out.name}: {n_rules} rules, {out.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
