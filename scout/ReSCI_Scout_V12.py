#!/usr/bin/env python3
# ============================================================
# 🦊 ReSCI SCOUT v12  -  Fast · Quiet · Focused Enumeration
# By J.ADIOS
# ------------------------------------------------------------
# Philosophie : "LinPEAS de l'énumération réseau".
#   - Profils de bruit (stealth / fast / deep / network) : TU choisis
#     le compromis discrétion <-> exhaustivité.
#   - Cible souple : IP, hostname, NOM NETBIOS, CIDR (réseau) ou -iL.
#   - Panneau QUICK WINS : les gains rapides remontent en premier.
#
# ⚠️  Usage strictement légal : uniquement sous ROE/NDA valide,
#     lab (HTB/THM), ou réseau dont tu es propriétaire.
# ============================================================

import argparse
import ipaddress
import logging
import os
import re
import shlex
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# UTF-8 forcé (évite les UnicodeEncodeError sous Windows/cp1252 ; no-op sous Linux)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ============================================================
# 🎨 BANNIÈRE & COULEURS
# ============================================================
BANNER = r"""
   ____       ____   ____ ___   ____                  _
  |  _ \ ___ / ___| / ___|_ _| / ___|  ___ ___  _   _| |_
  | |_) / _ \\___ \| |    | |  \___ \ / __/ _ \| | | | __|
  |  _ <  __/ ___) | |___ | |   ___) | (_| (_) | |_| | |_
  |_| \_\___|____/ \____|___| |____/ \___\___/ \__,_|\__|
  ─────────────────────────────────────────────────────────
  ReSCI Scout v12 · Fast · Quiet · Focused · By J.ADIOS
"""


class C:
    """Codes ANSI. Désactivés si --no-color ou sortie non-TTY."""
    R = "\033[91m"   # rouge   - critique / quick win fort
    G = "\033[92m"   # vert    - succès / accès
    Y = "\033[93m"   # jaune   - à regarder
    B = "\033[94m"   # bleu    - info
    C_ = "\033[96m"  # cyan    - titres
    D = "\033[2m"    # dim
    BOLD = "\033[1m"
    X = "\033[0m"    # reset

    @classmethod
    def disable(cls):
        for k in ("R", "G", "Y", "B", "C_", "D", "BOLD", "X"):
            setattr(cls, k, "")


# ============================================================
# ⚙️ PROFILS DE SCAN  (le coeur du système : bruit vs exhaustivité)
# ============================================================
@dataclass
class Profile:
    name: str
    desc: str
    # --- Découverte réseau (CIDR) ---
    discovery_args: str          # arguments nmap -sn
    # --- Scan de ports ---
    port_scan: str               # "rustscan" | "nmap-top" | "nmap-full"
    nmap_top: int                # top-ports si nmap-top
    nmap_timing: str             # -T2 .. -T4
    nmap_extra: str              # flags nmap détaillé (-sV, -sC, -O, -A...)
    scan_delay: str              # "" ou "--scan-delay 50ms"
    udp: bool
    # --- Enum web ---
    web_wordlist_key: str        # "common" | "medium"
    web_threads: int
    web_delay: str               # gobuster --delay
    web_exts: str
    do_nikto: bool
    do_vhost: bool
    do_recursive: bool
    # --- Enum services ---
    do_brute: bool               # dnsrecon brute, snmp community sweep...
    do_os_detect: bool
    aggressive_scripts: bool     # nmap --script vuln etc.
    max_hosts_parallel: int


PROFILES: Dict[str, Profile] = {
    # 🤫 STEALTH : le plus discret possible. SYN scan lent, top ports,
    #    aucune brute-force, pas de nikto/OS-detect/vhost. On accepte de
    #    rater des choses en échange d'un profil réseau minimal.
    "stealth": Profile(
        name="stealth",
        desc="Silencieux : SYN -T2, top-200, aucune brute-force",
        discovery_args="-sn -PS22,80,443,445,3389 -PE --max-retries 1",
        port_scan="nmap-top", nmap_top=200, nmap_timing="-T2",
        nmap_extra="-sS -sV --version-intensity 2 -Pn --max-retries 1",
        scan_delay="--scan-delay 40ms", udp=False,
        web_wordlist_key="common", web_threads=8, web_delay="150ms",
        web_exts="php,html,txt", do_nikto=False, do_vhost=False,
        do_recursive=False, do_brute=False, do_os_detect=False,
        aggressive_scripts=False, max_hosts_parallel=1,
    ),
    # ⚡ FAST : le mode "gagner du temps". Rapide, quick-wins, bruit modéré.
    "fast": Profile(
        name="fast",
        desc="Rapide : rustscan + nmap -sV -sC, wordlist common, quick-wins",
        discovery_args="-sn -T4",
        port_scan="rustscan", nmap_top=1000, nmap_timing="-T4",
        nmap_extra="-sV -sC -Pn --max-retries 2",
        scan_delay="", udp=False,
        web_wordlist_key="common", web_threads=30, web_delay="0",
        web_exts="php,html,txt,js,bak,old,zip,conf", do_nikto=False,
        do_vhost=True, do_recursive=False, do_brute=False,
        do_os_detect=False, aggressive_scripts=False, max_hosts_parallel=3,
    ),
    # 🔬 DEEP : équivalent du comportement V11 (tout, agressif).
    "deep": Profile(
        name="deep",
        desc="Profond : full-port, -A -O, nikto, vhost, brute, récursif",
        discovery_args="-sn -T4",
        port_scan="nmap-full", nmap_top=65535, nmap_timing="-T4",
        nmap_extra="-sC -sV -O -A -Pn --max-retries 2",
        scan_delay="", udp=True,
        web_wordlist_key="medium", web_threads=40, web_delay="0",
        web_exts="php,html,txt,js,bak,old,zip,tar,gz,conf,sql", do_nikto=True,
        do_vhost=True, do_recursive=True, do_brute=True,
        do_os_detect=True, aggressive_scripts=True, max_hosts_parallel=2,
    ),
    # 🗺️ NETWORK : cartographie de subnet. Léger par host (fingerprint),
    #    pas d'enum profonde : on veut la carte, pas le loot.
    "network": Profile(
        name="network",
        desc="Cartographie subnet : host discovery + fingerprint léger",
        discovery_args="-sn -T4",
        port_scan="nmap-top", nmap_top=100, nmap_timing="-T4",
        nmap_extra="-sV --version-intensity 0 -Pn --max-retries 1",
        scan_delay="", udp=False,
        web_wordlist_key="common", web_threads=20, web_delay="0",
        web_exts="php,html,txt", do_nikto=False, do_vhost=False,
        do_recursive=False, do_brute=False, do_os_detect=False,
        aggressive_scripts=False, max_hosts_parallel=8,
    ),
}

# ============================================================
# 📚 WORDLISTS  (auto-détection multi-chemins : Kali / Seclists / Parrot)
# ============================================================
WORDLIST_CANDIDATES = {
    "common": [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
    ],
    "medium": [
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ],
    "vhost": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    ],
}

WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 3000,
             5000, 9000, 9090, 9443, 10000}

# TLD à garder même hors sources "fortes" (contextes CTF / AD interne)
INTERESTING_TLDS = {"htb", "thm", "local", "corp", "lab", "internal", "box",
                    "vm", "home", "dev", "test", "intra", "ad", "win", "offsec"}

# Domaines "bruit" à ignorer (schémas, CDN, éditeurs de certifs/libs...)
NOISE_DOMAINS = {
    "example.com", "example.org", "example.net", "w3.org", "schema.org",
    "microsoft.com", "windows.com", "verisign", "digicert", "sectigo",
    "letsencrypt", "nginx.org", "apache.org", "php.net", "jquery",
    "bootstrap", "googleapis", "gstatic", "cloudflare", "mozilla",
    "openssl", "ubuntu.com", "debian.org", "kali.org", "json.org",
    "purl.org", "gnu.org", "oasis-open", "xml.org", "font-awesome",
    "fontawesome", "jsdelivr", "unpkg", "cdnjs", "sourceforge",
}


def find_wordlist(key: str) -> Optional[str]:
    for path in WORDLIST_CANDIDATES.get(key, []):
        if Path(path).exists():
            return path
    return None


# ============================================================
# 🔎 QUICK WINS  (le coeur "LinPEAS" : tout remonte ici, priorisé)
# ============================================================
@dataclass
class QuickWin:
    severity: int          # 3=critique(rouge) 2=intéressant(jaune) 1=info(bleu)
    host: str
    title: str
    detail: str = ""


QUICK_WINS: List[QuickWin] = []


def add_win(severity: int, host: str, title: str, detail: str = ""):
    QUICK_WINS.append(QuickWin(severity, host, title, detail))
    color = {3: C.R, 2: C.Y, 1: C.B}.get(severity, C.B)
    tag = {3: "!!", 2: "+ ", 1: "i "}.get(severity, "  ")
    line = f"  {color}[{tag}] {host:<15} {title}{C.X}"
    if detail:
        line += f" {C.D}— {detail}{C.X}"
    print(line)


# ============================================================
# 🛠️ UTILS
# ============================================================
def tool_exists(tool: str) -> bool:
    return subprocess.run(f"command -v {shlex.quote(tool)} >/dev/null 2>&1",
                          shell=True).returncode == 0


def run(cmd: str, outfile: Optional[Path] = None, timeout: int = 300,
        allow_fail: bool = True) -> bool:
    """Exécute une commande, capture vers outfile. Retourne True si rc==0."""
    log = logging.getLogger("scout")
    log.debug(f"[cmd] {cmd[:180]}")
    try:
        if outfile:
            outfile.parent.mkdir(parents=True, exist_ok=True)
            with outfile.open("w", encoding="utf-8") as f:
                r = subprocess.run(cmd, shell=True, stdout=f,
                                   stderr=subprocess.STDOUT, timeout=timeout)
        else:
            r = subprocess.run(cmd, shell=True, timeout=timeout)
        if r.returncode != 0 and not allow_fail:
            log.warning(f"[rc={r.returncode}] {cmd[:80]}")
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        log.warning(f"[timeout {timeout}s] {cmd[:80]}")
        return False
    except Exception as e:
        log.error(f"[err] {e}")
        return False


def run_capture(cmd: str, timeout: int = 60) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout)
        return r.stdout or ""
    except Exception:
        return ""


def read(path: Path) -> str:
    try:
        return path.read_text(errors="ignore") if path.exists() else ""
    except Exception:
        return ""


def setup_logging(base: Path, debug: bool) -> logging.Logger:
    log = logging.getLogger("scout")
    log.setLevel(logging.DEBUG if debug else logging.INFO)
    log.handlers.clear()
    fh = logging.FileHandler(base / "scout.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if debug else logging.INFO)
    ch.setFormatter(logging.Formatter(f"{C.D}%(message)s{C.X}"))
    log.addHandler(fh)
    log.addHandler(ch)
    return log


# ============================================================
# 🎯 RÉSOLUTION DE CIBLE  (IP / hostname / NetBIOS / CIDR / fichier)
# ============================================================
def classify_target(t: str) -> str:
    """Retourne : 'cidr' | 'ip' | 'hostname' | 'netbios'."""
    if "/" in t:
        try:
            ipaddress.ip_network(t, strict=False)
            return "cidr"
        except ValueError:
            pass
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    # hostname = contient un point ou label DNS valide
    if "." in t and re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$', t):
        return "hostname"
    # sinon : nom NetBIOS (label unique, <=15 chars)
    if re.match(r'^[a-zA-Z0-9_\-]{1,15}$', t):
        return "netbios"
    return "hostname"


def resolve_netbios(name: str, log: logging.Logger) -> Optional[str]:
    """Résout un nom NetBIOS -> IP via nmblookup (ou nbtscan fallback)."""
    if tool_exists("nmblookup"):
        out = run_capture(f"nmblookup {shlex.quote(name)}", timeout=15)
        # format:  10.10.10.5 NAME<00>
        m = re.search(r'^(\d{1,3}(?:\.\d{1,3}){3})\s', out, re.MULTILINE)
        if m:
            log.info(f"[netbios] {name} -> {m.group(1)}")
            return m.group(1)
    # fallback : résolution DNS classique (parfois le nom est dans /etc/hosts)
    try:
        ip = socket.gethostbyname(name)
        log.info(f"[dns] {name} -> {ip}")
        return ip
    except socket.gaierror:
        log.warning(f"[!] Impossible de résoudre le nom NetBIOS: {name}")
        return None


def resolve_hostname(name: str, log: logging.Logger) -> Optional[str]:
    try:
        ip = socket.gethostbyname(name)
        log.info(f"[dns] {name} -> {ip}")
        return ip
    except socket.gaierror:
        log.warning(f"[!] Résolution DNS échouée: {name} (ajoute-le à /etc/hosts ?)")
        return None


def netbios_info(ip: str, host_dir: Path, log: logging.Logger) -> Optional[str]:
    """nmblookup -A <ip> pour récupérer nom/domaine NetBIOS. Retourne le nom."""
    if not tool_exists("nmblookup"):
        return None
    out = run_capture(f"nmblookup -A {shlex.quote(ip)}", timeout=15)
    if out.strip():
        (host_dir / "netbios.txt").write_text(out, encoding="utf-8")
    m = re.search(r'^\s*(\S+)\s+<00>\s+-\s+(?:<GROUP>\s+)?[BMH]', out, re.MULTILINE)
    if m:
        nb = m.group(1)
        log.info(f"[netbios] {ip} = {nb}")
        return nb
    return None


# ============================================================
# 🌐 DÉCOUVERTE RÉSEAU  (host discovery + NetBIOS sweep)
# ============================================================
def discover_hosts(cidr: str, prof: Profile, base: Path,
                   log: logging.Logger) -> List[str]:
    """Host discovery sur un CIDR. Retourne la liste des IP vivantes."""
    log.info(f"{C.C_}[*] Découverte des hôtes sur {cidr}...{C.X}")
    scan_dir = base / "_network"
    scan_dir.mkdir(parents=True, exist_ok=True)
    live: List[str] = []

    # nmap -sn avec sortie greppable
    grep_out = scan_dir / "discovery.gnmap"
    run(f"nmap {prof.discovery_args} -oG {shlex.quote(str(grep_out))} "
        f"{shlex.quote(cidr)}", scan_dir / "discovery.txt", timeout=600)
    for line in read(grep_out).splitlines():
        m = re.match(r'Host:\s+(\d{1,3}(?:\.\d{1,3}){3})\s.*Status:\s+Up', line)
        if m:
            live.append(m.group(1))

    # NetBIOS sweep (donne les noms Windows d'un coup, peu bruyant)
    if tool_exists("nbtscan"):
        nb_out = run_capture(f"nbtscan -r {shlex.quote(cidr)}", timeout=120)
        (scan_dir / "nbtscan.txt").write_text(nb_out, encoding="utf-8")
        for line in nb_out.splitlines():
            m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)', line)
            if m and m.group(1) not in live:
                live.append(m.group(1))

    live = sorted(set(live), key=lambda ip: tuple(int(o) for o in ip.split(".")))
    log.info(f"{C.G}[+] {len(live)} hôte(s) vivant(s) : {', '.join(live) or 'aucun'}{C.X}")
    (scan_dir / "live_hosts.txt").write_text("\n".join(live), encoding="utf-8")
    return live


# ============================================================
# 🔓 SCAN DE PORTS  (profil-aware)
# ============================================================
def scan_ports(ip: str, prof: Profile, host_dir: Path,
               log: logging.Logger) -> List[int]:
    scan_dir = host_dir / "scans"
    scan_dir.mkdir(parents=True, exist_ok=True)
    ip_q = shlex.quote(ip)
    ports: set = set()

    if prof.port_scan == "rustscan" and tool_exists("rustscan"):
        out = scan_dir / "rustscan.txt"
        run(f"rustscan -a {ip_q} --ulimit 5000 -b 1000 --no-config -g", out,
            timeout=600)
        for m in re.finditer(r"(\d+)/(?:tcp|udp)", read(out)):
            ports.add(int(m.group(1)))
        for m in re.finditer(r"->\s*\[([\d,]+)\]", read(out)):
            for p in m.group(1).split(","):
                if p.strip().isdigit():
                    ports.add(int(p.strip()))
    elif prof.port_scan == "nmap-full":
        out = scan_dir / "nmap_allports.txt"
        run(f"nmap -p- --min-rate 1500 {prof.nmap_timing} -Pn {ip_q} "
            f"{prof.scan_delay}", out, timeout=1800)
        for m in re.finditer(r"(\d+)/tcp\s+open", read(out)):
            ports.add(int(m.group(1)))
    else:  # nmap-top
        out = scan_dir / "nmap_topports.txt"
        run(f"nmap --top-ports {prof.nmap_top} {prof.nmap_timing} -Pn {ip_q} "
            f"{prof.scan_delay}", out, timeout=900)
        for m in re.finditer(r"(\d+)/tcp\s+open", read(out)):
            ports.add(int(m.group(1)))

    log.info(f"{C.G}[+] {ip} : {len(ports)} port(s) ouvert(s) : "
             f"{sorted(ports)}{C.X}")
    return sorted(ports)


def deep_scan(ip: str, ports: List[int], prof: Profile, host_dir: Path,
              log: logging.Logger):
    """Scan détaillé nmap (services/scripts/os selon profil) sur ports ouverts."""
    if not ports:
        return
    scan_dir = host_dir / "scans"
    port_str = ",".join(map(str, ports))
    ip_q = shlex.quote(ip)
    extra = prof.nmap_extra
    if prof.aggressive_scripts:
        extra += " --script vuln"
    run(f"nmap {extra} {prof.nmap_timing} -p {port_str} {ip_q} "
        f"{prof.scan_delay} -oA {shlex.quote(str(scan_dir / 'nmap_tcp'))}",
        scan_dir / "nmap_tcp.txt", timeout=1800)

    if prof.udp:
        run(f"nmap -sU --top-ports 50 {prof.nmap_timing} {ip_q}",
            scan_dir / "nmap_udp.txt", timeout=900)

    # Quick wins depuis les scripts nmap
    nmap_out = read(scan_dir / "nmap_tcp.txt")
    for m in re.finditer(r"\|\s*(smb-vuln-\S+|ssl-heartbleed|ms\d+-\d+).*",
                         nmap_out):
        if "VULNERABLE" in nmap_out[m.start():m.start() + 400]:
            add_win(3, ip, f"Vuln nmap : {m.group(1)}")


def detect_http(host_dir: Path) -> Dict[int, str]:
    """Détecte les services HTTP/HTTPS depuis la sortie nmap."""
    services: Dict[int, str] = {}
    content = read(host_dir / "scans" / "nmap_tcp.txt")
    for line in content.splitlines():
        m = re.match(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?', line)
        if not m:
            continue
        port, svc, det = int(m.group(1)), m.group(2).lower(), (m.group(3) or "").lower()
        full = f"{svc} {det}"
        is_http = (svc in ("http", "https", "http-proxy", "http-alt", "ssl/http")
                   or port in WEB_PORTS
                   or any(k in full for k in ("http", "nginx", "apache", "iis",
                                              "tomcat", "werkzeug", "node")))
        if is_http:
            scheme = "https" if (port in (443, 8443, 9443, 10443)
                                 or "ssl" in full or svc == "https") else "http"
            services[port] = scheme
    return services


# ============================================================
# 🌐 ENUM WEB  (profil-aware)
# ============================================================
def sanitize(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9._\-]', '_', s)


def _clean_domains(cands, ip: str, tld_only: bool = False) -> set:
    out = set()
    for d in cands:
        d = (d or "").strip().strip('.').lstrip('*').strip('.').lower()
        if not d or d == ip or "." not in d:
            continue
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', d):
            continue
        if any(n in d for n in NOISE_DOMAINS):
            continue
        if tld_only and d.rsplit('.', 1)[-1] not in INTERESTING_TLDS:
            continue
        out.add(d)
    return out


def harvest_hostnames(ip: str, host_dir: Path, log: logging.Logger,
                      domain_hint: Optional[str] = None) -> List[str]:
    """Récolte les hostnames/domaines vus par nmap : redirections HTTP,
    certificats TLS (CN/SAN), smb-os-discovery/LDAP, + TLD intéressants.
    C'est le 'site.htb' qu'on repère habituellement à la main."""
    nmap = (read(host_dir / "scans" / "nmap_tcp.txt") + "\n"
            + read(host_dir / "scans" / "nmap_tcp.xml"))
    strong, generic = set(), set()

    # Redirections HTTP (http-title / Location)
    for m in re.finditer(r'(?:Did not follow redirect to|redirect to|'
                         r'Location:)\s*https?://([A-Za-z0-9._\-]+)', nmap, re.I):
        strong.add(m.group(1))
    # Certificats TLS : commonName + Subject Alternative Name DNS:
    for m in re.finditer(r'commonName=([A-Za-z0-9.*_\-]+)', nmap):
        strong.add(m.group(1))
    for m in re.finditer(r'DNS:([A-Za-z0-9.*_\-]+)', nmap):
        strong.add(m.group(1))
    # SMB / LDAP / AD (smb-os-discovery, rdp-ntlm-info…)
    for pat in (r'Domain name:\s*([A-Za-z0-9.\-]+)',
                r'FQDN:\s*([A-Za-z0-9.\-]+)',
                r'Computer name:\s*([A-Za-z0-9.\-]+)',
                r'DNS_Domain_Name:\s*([A-Za-z0-9.\-]+)',
                r'DNS_Computer_Name:\s*([A-Za-z0-9.\-]+)',
                r'DNS_Tree_Name:\s*([A-Za-z0-9.\-]+)'):
        for m in re.finditer(pat, nmap, re.I):
            strong.add(m.group(1))
    # TLD intéressants n'importe où dans la sortie
    tld_re = r'\b([a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?:' + "|".join(INTERESTING_TLDS) + r'))\b'
    for m in re.finditer(tld_re, nmap, re.I):
        generic.add(m.group(1))

    if domain_hint:
        strong.add(domain_hint)

    domains = sorted(_clean_domains(strong, ip) | _clean_domains(generic, ip, tld_only=True))
    if domains:
        (host_dir / "discovered_domains.txt").write_text(
            "\n".join(domains) + "\n", encoding="utf-8")
        log.info(f"{C.G}[+] {ip} : domaines découverts dans nmap : "
                 f"{', '.join(domains)}{C.X}")
    return domains


def update_etc_hosts(ip: str, domains: List[str], auto: bool,
                     log: logging.Logger, host_dir: Path):
    """Écrit un fichier prêt à coller dans /etc/hosts ; l'ajoute
    automatiquement si --auto-hosts (direct ou via sudo)."""
    entries = [f"{ip}\t{d}" for d in domains]
    add_file = host_dir / "add_to_hosts.txt"
    add_file.write_text("\n".join(entries) + "\n", encoding="utf-8")

    if not auto:
        log.info(f"{C.Y}[hosts] Ajout manuel : "
                 f"cat {add_file} | sudo tee -a /etc/hosts{C.X}")
        return

    hp = Path("/etc/hosts")
    try:
        existing = hp.read_text(errors="ignore") if hp.exists() else ""
        to_add = [e for e in entries if e.split('\t')[1] not in existing]
        if not to_add:
            return
        try:
            with hp.open("a", encoding="utf-8") as f:
                f.write("\n" + "\n".join(to_add) + "\n")
            log.info(f"{C.G}[hosts] /etc/hosts mis à jour : "
                     f"{', '.join(e.split(chr(9))[1] for e in to_add)}{C.X}")
        except PermissionError:
            cmd = ("printf '%s\\n' " + " ".join(shlex.quote(e) for e in to_add)
                   + " | sudo tee -a /etc/hosts >/dev/null")
            if run(cmd, timeout=15):
                log.info(f"{C.G}[hosts] /etc/hosts mis à jour (sudo){C.X}")
            else:
                log.warning(f"{C.Y}[hosts] échec sudo — ajoute à la main : "
                            f"cat {add_file} | sudo tee -a /etc/hosts{C.X}")
    except Exception as e:
        log.warning(f"[hosts] MAJ impossible : {e}")


def enum_web(ip: str, port: int, scheme: str, prof: Profile, host_dir: Path,
             log: logging.Logger, user: Optional[str], pw: Optional[str],
             vhost: Optional[str] = None):
    """Énumère un service web. Si vhost est fourni, on cible toujours l'IP
    mais avec l'en-tête `Host: vhost` → routage vhost sans dépendre de
    /etc/hosts. Sinon on énumère l'IP nue."""
    label = sanitize(vhost) if vhost else "ip"
    web = host_dir / "web" / f"port_{port}_{label}"
    web.mkdir(parents=True, exist_ok=True)
    disp = f"{scheme}://{vhost or ip}:{port}"       # affichage
    req = f"{scheme}://{ip}:{port}"                  # requête réelle (IP)
    req_q = shlex.quote(req)
    hdr = f"-H {shlex.quote('Host: ' + vhost)}" if vhost else ""       # curl/gobuster
    wa_hdr = f"--header {shlex.quote('Host: ' + vhost)}" if vhost else ""  # whatweb
    log.info(f"{C.C_}[*] Web {disp}{C.X}")

    # Headers
    run(f"curl -sSI -k -m 10 {hdr} {req_q}", web / "headers.txt", timeout=15)

    # Fingerprint léger (whatweb) — respecte le vhost
    if tool_exists("whatweb") and prof.name != "network":
        run(f"whatweb -a 1 --no-errors {wa_hdr} {req_q}", web / "whatweb.txt",
            timeout=60)

    # robots / .git / fichiers sensibles courants (cheap, gros ROI)
    for probe, sev, plabel in [
        ("/robots.txt", 1, "robots.txt exposé"),
        ("/.git/HEAD", 3, ".git exposé (source code !)"),
        ("/.env", 3, ".env exposé (secrets !)"),
        ("/server-status", 2, "Apache server-status"),
        ("/phpinfo.php", 2, "phpinfo() exposé"),
    ]:
        code = run_capture(
            f"curl -sk -o /dev/null -m 8 {hdr} -w '%{{http_code}}' "
            f"{shlex.quote(req + probe)}", timeout=12).strip()
        if code in ("200", "301", "302"):
            add_win(sev, ip, plabel, f"{disp}{probe} [{code}]")

    # Directory listing sur la racine
    body = run_capture(f"curl -sk -m 10 {hdr} {req_q}", timeout=15)
    if re.search(r'<title>\s*Index of /', body, re.IGNORECASE):
        add_win(2, ip, f"Directory listing actif :{port}", disp)

    # Auth basic
    auth = ""
    if user and pw:
        auth = f"-U {shlex.quote(user)} -P {shlex.quote(pw)}"

    # Gobuster (profil-aware : wordlist, threads, delay) — respecte le vhost
    wl = find_wordlist(prof.web_wordlist_key)
    if tool_exists("gobuster") and wl:
        delay = f"--delay {prof.web_delay}" if prof.web_delay not in ("", "0") else ""
        log.info(f"[dir] gobuster {prof.web_wordlist_key} "
                 f"t={prof.web_threads} → {disp}")
        run(f"gobuster dir -u {req_q} -w {shlex.quote(wl)} {hdr} "
            f"-t {prof.web_threads} -k -x {prof.web_exts} -b 404,403 "
            f"{delay} {auth} --no-error -q -o {shlex.quote(str(web / 'gobuster.txt'))}",
            timeout=1200 if prof.name == "deep" else 600)
        for line in read(web / "gobuster.txt").splitlines():
            low = line.lower()
            if any(x in low for x in (".bak", ".old", ".zip", ".sql", ".config",
                                      ".env", "backup", "admin", "login", "upload")):
                add_win(2, ip, "Chemin sensible", f"{disp} {line.strip()[:70]}")

    # Nikto (deep uniquement) — -vhost pour le routage
    if prof.do_nikto and tool_exists("nikto"):
        vh = f"-vhost {shlex.quote(vhost)}" if vhost else ""
        run(f"nikto -h {req_q} {vh} -Tuning 123bde -maxtime 180 "
            f"-output {shlex.quote(str(web / 'nikto.txt'))}", timeout=220)

    # Vhost fuzzing (seulement sur l'IP nue, ports 80/443)
    if vhost is None and prof.do_vhost and port in (80, 443) and tool_exists("ffuf"):
        vwl = find_wordlist("vhost")
        base_dom = None  # on fuzz sous le 1er domaine connu si dispo, sinon l'IP
        dd = read(host_dir / "discovered_domains.txt").splitlines()
        base_dom = dd[0] if dd else ip
        if vwl:
            run(f"ffuf -w {shlex.quote(vwl)} -u {req_q} "
                f"-H {shlex.quote('Host: FUZZ.' + base_dom)} "
                f"-t 40 -ac -fc 404,400 -s "
                f"-o {shlex.quote(str(web / 'vhosts.json'))} -of json",
                web / "vhosts.txt", timeout=300)


def enum_web_all(ip: str, http: Dict[int, str], domains: List[str],
                 prof: Profile, host_dir: Path, log: logging.Logger,
                 user: Optional[str], pw: Optional[str]):
    """Décide QUOI énumérer par port : l'IP nue et/ou les vhosts découverts.
    Si l'IP redirige vers un domaine, on énumère directement ce domaine
    (au lieu de perdre du temps sur la page par défaut de l'IP)."""
    cap = 1 if prof.name == "stealth" else 3
    for port, scheme in sorted(http.items()):
        # Pré-sonde : l'IP nue redirige-t-elle vers un vhost ?
        h = run_capture(
            f"curl -sSI -k -m 8 {shlex.quote(f'{scheme}://{ip}:{port}')}", timeout=12)
        redirect = None
        mm = re.search(r'Location:\s*https?://([A-Za-z0-9._\-]+)', h, re.I)
        if mm and not re.match(r'^\d+\.\d+\.\d+\.\d+$', mm.group(1)):
            redirect = mm.group(1).lower()
            add_win(2, ip, f"Redirection :{port}", f"→ {redirect}")

        # Liste ordonnée des cibles (None = IP nue)
        all_domains = list(dict.fromkeys(
            ([redirect] if redirect else []) + list(domains)))
        targets: List[Optional[str]] = []
        if redirect:
            targets.append(redirect)          # prioritaire, on saute l'IP nue
        else:
            targets.append(None)              # IP nue
        for d in all_domains:
            if d and d != redirect and len(targets) <= cap:
                targets.append(d)

        shown = [t or ip for t in targets]
        log.info(f"{C.B}[web] port {port} → cibles : {shown}{C.X}")
        for vhost in targets:
            enum_web(ip, port, scheme, prof, host_dir, log, user, pw, vhost)


# ============================================================
# 🧠 ENUM SMB / AD  (profil-aware)
# ============================================================
def enum_smb(ip: str, prof: Profile, host_dir: Path, log: logging.Logger,
             user: Optional[str], pw: Optional[str], domain: Optional[str]):
    smb = host_dir / "smb"
    smb.mkdir(parents=True, exist_ok=True)
    ip_q = shlex.quote(ip)
    log.info(f"{C.C_}[*] SMB {ip}{C.X}")

    nxc = "netexec" if tool_exists("netexec") else ("nxc" if tool_exists("nxc") else None)

    if nxc:
        # Bannière + signing (quick win si signing:False)
        info = run_capture(f"{nxc} smb {ip_q}", timeout=60)
        (smb / "nxc_info.txt").write_text(info, encoding="utf-8")
        if re.search(r'signing:\s*False', info, re.IGNORECASE):
            add_win(2, ip, "SMB signing désactivé", "relais NTLM possible")
        dm = re.search(r'\(domain:([^)]+)\)', info)
        if dm:
            add_win(1, ip, "Domaine AD", dm.group(1))

        if user and pw:
            a = f"-u {shlex.quote(user)} -p {shlex.quote(pw)}"
            if domain:
                a += f" -d {shlex.quote(domain)}"
            run(f"{nxc} smb {ip_q} {a} --shares", smb / "nxc_shares.txt", timeout=120)
            run(f"{nxc} smb {ip_q} {a} --users", smb / "nxc_users.txt", timeout=120)
            run(f"{nxc} smb {ip_q} {a} --generate-hosts-file "
                f"{shlex.quote(str(smb / 'hosts'))}", smb / "nxc_hosts.txt", timeout=60)
        else:
            # Null / guest session
            for label, a in [("null", "-u '' -p ''"), ("guest", "-u guest -p ''")]:
                out = smb / f"nxc_shares_{label}.txt"
                run(f"{nxc} smb {ip_q} {a} --shares", out, timeout=90)
                sh = read(out)
                if re.search(r'\bREAD\b', sh):
                    add_win(3, ip, f"SMB {label}: partage lisible !",
                            "session anonyme OK")
                if re.search(r'\bWRITE\b', sh):
                    add_win(3, ip, f"SMB {label}: partage inscriptible !")

    # smbclient fallback anonyme
    if tool_exists("smbclient") and not user:
        out = smb / "smbclient_anon.txt"
        run(f"smbclient -L //{ip_q}/ -N", out, timeout=60)
        if re.search(r'Disk|IPC', read(out)):
            add_win(2, ip, "SMB : partages listés (anon)", "smbclient -N")

    # enum4linux-ng seulement hors stealth (bruyant)
    if prof.name in ("fast", "deep") and tool_exists("enum4linux-ng"):
        run(f"enum4linux-ng -A {ip_q}", smb / "enum4linux.txt", timeout=400)


# ============================================================
# 📡 AUTRES SERVICES  (profil-aware)
# ============================================================
def enum_ftp(ip: str, host_dir: Path, log: logging.Logger):
    ftp = host_dir / "ftp"
    ftp.mkdir(parents=True, exist_ok=True)
    out = ftp / "anon.txt"
    run(f"curl -sS -m 20 ftp://{shlex.quote(ip)}/ --user anonymous:anonymous",
        out, timeout=30)
    body = read(out)
    if body.strip() and "530" not in body and "Access denied" not in body:
        add_win(3, ip, "FTP anonyme autorisé", "curl ftp:// --user anonymous")


def enum_snmp(ip: str, prof: Profile, host_dir: Path, log: logging.Logger):
    if not tool_exists("snmpwalk"):
        return
    snmp = host_dir / "snmp"
    snmp.mkdir(parents=True, exist_ok=True)
    # stealth : uniquement "public"
    communities = ["public"] if not prof.do_brute else ["public", "private", "community"]
    for comm in communities:
        out = snmp / f"walk_{comm}.txt"
        run(f"snmpwalk -v2c -c {shlex.quote(comm)} -t 3 -r 1 {shlex.quote(ip)} "
            f"1.3.6.1.2.1", out, timeout=120)
        if len(read(out)) > 100:
            add_win(3, ip, f"SNMP community '{comm}' valide", "dump possible")
            break


def enum_dns(ip: str, prof: Profile, host_dir: Path, log: logging.Logger,
             domain: Optional[str]):
    dns = host_dir / "dns"
    dns.mkdir(parents=True, exist_ok=True)
    if domain:
        out = dns / "axfr.txt"
        run(f"dig @{shlex.quote(ip)} {shlex.quote(domain)} AXFR", out, timeout=30)
        if re.search(r'\bIN\b.*\b(A|CNAME|MX|NS)\b', read(out)) and \
           "Transfer failed" not in read(out):
            add_win(3, ip, "Zone transfer (AXFR) réussi", domain)


def enum_nfs(ip: str, host_dir: Path, log: logging.Logger):
    if not tool_exists("showmount"):
        return
    nfs = host_dir / "nfs"
    nfs.mkdir(parents=True, exist_ok=True)
    out = nfs / "showmount.txt"
    run(f"showmount -e {shlex.quote(ip)}", out, timeout=30)
    if "/" in read(out):
        add_win(2, ip, "NFS export accessible", "showmount -e")


# ============================================================
# 📊 RAPPORT PAR HOST
# ============================================================
def write_host_report(ip: str, nb_name: Optional[str], ports: List[int],
                      http: Dict[int, str], host_dir: Path, prof: Profile):
    md = [f"# 🦊 ReSCI Scout — {ip}"]
    if nb_name:
        md.append(f"**NetBIOS** : `{nb_name}`  ")
    md.append(f"\n**Profil** : {prof.name} · **Date** : "
              f"{datetime.now():%Y-%m-%d %H:%M}\n")
    md.append(f"**Ports ouverts** ({len(ports)}) : `{ports}`\n")

    # Quick wins de ce host
    host_wins = [w for w in QUICK_WINS if w.host == ip]
    if host_wins:
        md.append("## 🎯 Quick Wins\n")
        for w in sorted(host_wins, key=lambda x: -x.severity):
            icon = {3: "🔴", 2: "🟡", 1: "🔵"}[w.severity]
            md.append(f"- {icon} **{w.title}** {w.detail}")
        md.append("")

    nmap = read(host_dir / "scans" / "nmap_tcp.txt")
    if nmap:
        md.append("## 📊 Services (nmap)\n```\n" + nmap[:6000] + "\n```\n")

    dom_file = read(host_dir / "discovered_domains.txt").strip()
    if dom_file:
        md.append("## 🌍 Domaines découverts (nmap → énum web)\n")
        for d in dom_file.splitlines():
            md.append(f"- `{d}`")
        md.append("")

    if http:
        md.append("## 🌐 Web\n")
        for port, scheme in sorted(http.items()):
            for wdir in sorted((host_dir / "web").glob(f"port_{port}_*")):
                target = wdir.name.replace(f"port_{port}_", "")
                md.append(f"### {scheme}://{target if target != 'ip' else ip}:{port}")
                gob = read(wdir / "gobuster.txt")
                if gob:
                    md.append("```\n" + gob[:2500] + "\n```")

    (host_dir / "REPORT.md").write_text("\n".join(md), encoding="utf-8")


# ============================================================
# 🚀 ORCHESTRATION PAR HOST
# ============================================================
def scout_host(ip: str, prof: Profile, base: Path, log: logging.Logger,
               user: Optional[str], pw: Optional[str], domain: Optional[str],
               auto_hosts: bool = False):
    host_dir = base / "hosts" / ip
    host_dir.mkdir(parents=True, exist_ok=True)
    log.info(f"\n{C.BOLD}{C.C_}{'='*60}\n[HOST] {ip}\n{'='*60}{C.X}")

    nb_name = netbios_info(ip, host_dir, log)

    ports = scan_ports(ip, prof, host_dir, log)
    if not ports:
        log.info(f"{C.D}[-] {ip} : aucun port ouvert, skip{C.X}")
        return
    deep_scan(ip, ports, prof, host_dir, log)
    http = detect_http(host_dir)

    # 🆕 Récolte des hostnames/domaines vus dans nmap (cert TLS, redirection,
    #    smb-os-discovery…) → injectés dans l'énum web + /etc/hosts.
    domains = harvest_hostnames(ip, host_dir, log, domain)
    if nb_name and domain and "." not in nb_name:
        combo = f"{nb_name.lower()}.{domain.lower()}"
        if combo not in domains:
            domains = sorted(set(domains) | {combo})
    if domains:
        add_win(2, ip, "Domaines découverts (nmap)", ", ".join(domains))
        update_etc_hosts(ip, domains, auto_hosts, log, host_dir)

    # Mode network : on s'arrête au fingerprint (pas d'enum profonde)
    if prof.name == "network":
        if http:
            add_win(1, ip, "Service(s) web", ", ".join(str(p) for p in http))
        if 445 in ports:
            add_win(1, ip, "SMB ouvert (445)", nb_name or "")
        write_host_report(ip, nb_name, ports, http, host_dir, prof)
        return

    # Enum ciblée selon ports réellement ouverts
    tasks = []
    if http:
        tasks.append(lambda: enum_web_all(ip, http, domains, prof, host_dir,
                                          log, user, pw))
    if 445 in ports or 139 in ports:
        tasks.append(lambda: enum_smb(ip, prof, host_dir, log, user, pw, domain))
    if 21 in ports:
        tasks.append(lambda: enum_ftp(ip, host_dir, log))
    if 161 in ports:
        tasks.append(lambda: enum_snmp(ip, prof, host_dir, log))
    if 53 in ports or domain:
        tasks.append(lambda: enum_dns(ip, prof, host_dir, log, domain))
    if 111 in ports or 2049 in ports:
        tasks.append(lambda: enum_nfs(ip, host_dir, log))

    workers = 1 if prof.name == "stealth" else 2
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed([ex.submit(t) for t in tasks]):
            try:
                fut.result()
            except Exception as e:
                log.error(f"[err enum] {e}")

    write_host_report(ip, nb_name, ports, http, host_dir, prof)


# ============================================================
# 📋 RÉSUMÉ FINAL
# ============================================================
def final_summary(base: Path, hosts: List[str], start: datetime):
    dur = datetime.now() - start
    print(f"\n{C.BOLD}{C.C_}{'='*60}{C.X}")
    print(f"{C.BOLD}🦊 SCOUT TERMINÉ{C.X}")
    print(f"{C.C_}{'='*60}{C.X}")
    print(f"⏱️  Durée   : {int(dur.total_seconds()//60)}m {int(dur.total_seconds()%60)}s")
    print(f"📁 Résultats: {base}")
    print(f"🖥️  Hôtes    : {len(hosts)}")

    if QUICK_WINS:
        print(f"\n{C.BOLD}🎯 QUICK WINS ({len(QUICK_WINS)}) — priorisés :{C.X}")
        for w in sorted(QUICK_WINS, key=lambda x: -x.severity):
            color = {3: C.R, 2: C.Y, 1: C.B}[w.severity]
            print(f"  {color}{w.host:<15} {w.title}{C.X} "
                  f"{C.D}{w.detail}{C.X}")
    else:
        print(f"\n{C.D}Aucun quick win détecté automatiquement — "
              f"regarde les rapports par host.{C.X}")

    # Rapport réseau global
    md = [f"# 🦊 ReSCI Scout — Rapport réseau\n",
          f"**Date** : {datetime.now():%Y-%m-%d %H:%M} · "
          f"**Durée** : {int(dur.total_seconds()//60)}m\n",
          f"## Hôtes ({len(hosts)})\n"]
    for h in hosts:
        wins = [w for w in QUICK_WINS if w.host == h]
        md.append(f"- **{h}** — [rapport](hosts/{h}/REPORT.md) "
                  f"— {len(wins)} quick win(s)")
    md.append("\n## 🎯 Quick Wins globaux\n")
    for w in sorted(QUICK_WINS, key=lambda x: -x.severity):
        icon = {3: "🔴", 2: "🟡", 1: "🔵"}[w.severity]
        md.append(f"- {icon} `{w.host}` **{w.title}** {w.detail}")
    md.append("\n---\n⚠️ Exploitation uniquement sous ROE/NDA valide.")
    (base / "NETWORK_REPORT.md").write_text("\n".join(md), encoding="utf-8")
    print(f"\n📄 Rapport réseau : {base / 'NETWORK_REPORT.md'}")
    print(f"{C.C_}{'='*60}{C.X}\n⚠️  Uniquement sous ROE/NDA valide. Bon pentest 🦊")


# ============================================================
# 🚀 MAIN
# ============================================================
def build_target_list(raw_targets: List[str], prof: Profile, base: Path,
                      log: logging.Logger) -> List[str]:
    """Transforme les cibles brutes (IP/host/netbios/cidr/fichier) en IPs."""
    ips: List[str] = []
    for t in raw_targets:
        kind = classify_target(t)
        if kind == "cidr":
            ips.extend(discover_hosts(t, prof, base, log))
        elif kind == "ip":
            ips.append(t)
        elif kind == "netbios":
            r = resolve_netbios(t, log)
            if r:
                ips.append(r)
        else:  # hostname
            r = resolve_hostname(t, log)
            if r:
                ips.append(r)
    # dédup en gardant l'ordre
    seen, out = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def main():
    parser = argparse.ArgumentParser(
        description="🦊 ReSCI Scout v12 — énumération rapide, discrète, focalisée",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  # Rapide sur une IP (gagner du temps + quick wins)
  %(prog)s 10.10.10.100

  # Discret (IDS-safe) sur une cible sensible
  %(prog)s 10.10.10.100 --profile stealth

  # Cartographier tout un réseau
  %(prog)s 10.10.10.0/24 --profile network

  # Cibler par nom NetBIOS
  %(prog)s DC01 --profile fast

  # Profond (= comportement V11) avec creds AD
  %(prog)s 10.10.10.100 --profile deep -u john -p 'Pass!' -d corp.htb

  # Liste de cibles
  %(prog)s -iL cibles.txt --profile fast
""")
    parser.add_argument("targets", nargs="*",
                        help="IP / hostname / nom NetBIOS / CIDR")
    parser.add_argument("-iL", dest="target_file",
                        help="Fichier de cibles (une par ligne)")
    parser.add_argument("--profile", choices=list(PROFILES.keys()),
                        default="fast",
                        help="Profil de bruit/vitesse (défaut: fast)")
    parser.add_argument("-u", "--username", help="User pour SMB/Web/AD")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("-d", "--domain", help="Domaine AD / DNS")
    parser.add_argument("--auto-hosts", action="store_true",
                        help="Ajoute auto les domaines découverts à /etc/hosts (sudo)")
    parser.add_argument("-o", "--output", help="Dossier de sortie")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--list-profiles", action="store_true",
                        help="Affiche les profils et quitte")
    args = parser.parse_args()

    if not sys.stdout.isatty() or args.no_color:
        C.disable()

    if args.list_profiles:
        print(BANNER)
        for name, p in PROFILES.items():
            print(f"{C.BOLD}{name:<9}{C.X} {p.desc}")
        sys.exit(0)

    if (args.username and not args.password) or (args.password and not args.username):
        parser.error("-u et -p vont ensemble")

    # Rassembler les cibles
    raw = list(args.targets)
    if args.target_file:
        raw += [l.strip() for l in Path(args.target_file).read_text().splitlines()
                if l.strip() and not l.startswith("#")]
    if not raw:
        parser.error("Aucune cible. Donne une IP/host/netbios/CIDR ou -iL fichier.")

    prof = PROFILES[args.profile]
    start = datetime.now()
    out_name = args.output or f"scout_{start:%Y%m%d_%H%M%S}"
    base = Path(out_name)
    base.mkdir(parents=True, exist_ok=True)

    print(BANNER)
    log = setup_logging(base, args.debug)
    log.info(f"{C.BOLD}[*] Profil : {prof.name} — {prof.desc}{C.X}")
    if prof.name == "stealth":
        log.info(f"{C.Y}[!] Mode stealth : plus lent, moins de ports, "
                 f"aucune brute-force. Tu peux rater des choses.{C.X}")

    # Vérif outils essentiels
    if not tool_exists("nmap"):
        log.error(f"{C.R}[X] nmap introuvable — indispensable. Installe-le.{C.X}")
        sys.exit(1)

    targets = build_target_list(raw, prof, base, log)
    if not targets:
        log.error(f"{C.R}[X] Aucune cible résolue.{C.X}")
        sys.exit(1)
    log.info(f"{C.G}[+] {len(targets)} cible(s) à énumérer{C.X}")

    print(f"\n{C.BOLD}🎯 QUICK WINS (temps réel) :{C.X}")

    # Énumération (hosts en parallèle selon profil)
    with ThreadPoolExecutor(max_workers=prof.max_hosts_parallel) as ex:
        futures = {ex.submit(scout_host, ip, prof, base, log,
                             args.username, args.password, args.domain,
                             args.auto_hosts): ip
                   for ip in targets}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                fut.result()
            except Exception as e:
                log.error(f"[err host {ip}] {e}")

    final_summary(base, targets, start)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interruption utilisateur{C.X}")
        sys.exit(1)
    except Exception as e:
        print(f"{C.R}[X] Erreur fatale : {e}{C.X}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
