#!/usr/bin/env python3
# ============================================================
# 🦊 RESCI ENUM FRAMEWORK v11
# By J.ADIOS
# ============================================================

import argparse
import subprocess
import shlex
import sys
import re
import os
import socket
import json
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List, Dict, Optional
import logging
import ipaddress

# ============================================================
# 🎨 BANNIÈRE
# ============================================================
BANNER = r"""
████████╗ ███████╗ ███████╗ ██████╗ ██╗
██╔══██╗██╔════╝ ██╔════╝██╔════╝ ██║
███████╔╝█████╗   ███████╗██║      ██║
██╔══██╗██╔══╝   ╚════██║██║      ██║
██║  ██║███████╗ ███████║╚██████╗ ██║
╚═╝  ╚═╝╚══════╝ ╚══════╝ ╚═════╝ ╚═╝
═══════════════════════════════════════
Framework ReSCI, Recon, Enum, IA Pentest
═══════════════════════════════════════
V11 - Auto Adaptive | Full Mode Default
"""

# ============================================================
# ⚙️ CONFIG
# ============================================================
WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 9000}
UDP_FAST_PORTS = "53,69,123,161,389"
NFS_PORTS = {111, 2049}
CRITICAL_PORTS = {21, 22, 23, 25, 88, 139, 445, 3389, 5985, 5986}

WORDLISTS = {
    "fast": "/usr/share/wordlists/dirb/common.txt",
    "full": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "default": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",  # Meilleur résultat test 01/01/26
}

VHOST_WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/seclists/Discovery/DNS/combined_subdomains.txt",
]

# ============================================================
# 🛡️ VALIDATION
# ============================================================
def validate_target(target: str) -> bool:
    """Valide que la cible est une IP ou hostname valide."""
    # Vérifier si c'est une IP valide
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Vérifier si c'est un hostname valide (RFC 1123)
    if len(target) > 253:
        return False

    # Hostname pattern: lettres, chiffres, tirets, points
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    if re.match(hostname_pattern, target):
        return True

    return False

# ============================================================
# 🛠️ LOGGING SETUP
# ============================================================
def setup_logging(base: Path, debug: bool = False):
    log_file = base / "resci_enum.log"
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

# ============================================================
# 🛠️ UTILS AMÉLIORÉS
# ============================================================
def tool_exists(tool: str) -> bool:
    """Vérifie si un outil est disponible dans le PATH."""
    return subprocess.run(
        f"command -v {shlex.quote(tool)} >/dev/null 2>&1",
        shell=True
    ).returncode == 0

def run(cmd: str, outfile: Optional[Path] = None, timeout: int = 300, allow_fail: bool = False) -> bool:
    """Exécute une commande avec gestion d'erreurs et timeout."""
    logger = logging.getLogger(__name__)
    logger.info(f"[🦊] {cmd[:150]}...")
    
    try:
        if outfile:
            outfile.parent.mkdir(parents=True, exist_ok=True)
            with outfile.open("w", encoding="utf-8") as f:
                result = subprocess.run(
                    cmd, 
                    shell=True, 
                    stdout=f, 
                    stderr=subprocess.STDOUT,
                    timeout=timeout
                )
        else:
            result = subprocess.run(cmd, shell=True, timeout=timeout)
        
        if result.returncode != 0:
            if not allow_fail:
                logger.warning(f"[⚠️] Commande terminée avec code {result.returncode}")
            return False
        return True
        
    except subprocess.TimeoutExpired:
        logger.error(f"[❌] Timeout ({timeout}s)")
        return False
    except Exception as e:
        logger.error(f"[❌] Erreur: {e}")
        return False

def setup_dirs(base: Path):
    """Crée la structure de répertoires."""
    dirs = [
        "scans", "dns", "web", "smb", "ftp",
        "ldap", "snmp", "nfs", "kerberos",
        "searchsploit", "ad", "loot", "notes", "exports"
    ]
    for d in dirs:
        (base / d).mkdir(parents=True, exist_ok=True)

def update_hosts_file(ip: str, domain: str, auto: bool = False):
    """Met à jour /etc/hosts si un nouveau domaine est découvert."""
    logger = logging.getLogger(__name__)
    
    # Ignorer si c'est une IP ou localhost
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) or domain in ["localhost", "127.0.0.1"]:
        return

    try:
        # Vérifier si le domaine est déjà résolu vers cette IP
        try:
            resolved_ip = socket.gethostbyname(domain)
            if resolved_ip == ip:
                return # Déjà configuré
        except socket.gaierror:
            pass # Non résolu

        entry = f"{ip}\t{domain}"
        
        if auto:
            try:
                # Tenter avec sudo via subprocess
                cmd = f"echo '{entry}' | sudo tee -a /etc/hosts"
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
                logger.info(f"[📝] /etc/hosts mis à jour: {entry}")
                return
            except Exception as e:
                logger.error(f"[❌] Échec mise à jour auto /etc/hosts: {e}")

        # Si pas auto ou échec, afficher la commande
        logger.info("\n" + "!"*60)
        logger.info(f"🚨 NOUVEAU DOMAINE DÉCOUVERT: {domain}")
        logger.info(f"👉 Commande suggérée: echo \"{ip} {domain}\" | sudo tee -a /etc/hosts")
        logger.info("!"*60 + "\n")

    except Exception as e:
        logger.error(f"[❌] Erreur gestion hosts: {e}")

# ============================================================
# 🔍 DÉTECTION DYNAMIQUE DES SERVICES HTTP
# ============================================================
def detect_http_services(base: Path) -> Dict[int, str]:
    """Parse nmap output pour détecter TOUS les services HTTP/HTTPS (AGRESSIF)."""
    logger = logging.getLogger(__name__)
    http_services = {}

    # Essayer plusieurs sources (format .nmap, .xml, puis stdout)
    nmap_files = [
        base / "scans" / "nmap_tcp.nmap",  # Format -oN (prioritaire)
        base / "scans" / "nmap_tcp.xml",   # Format XML (très fiable)
        base / "scans" / "nmap_tcp.txt"     # Stdout (fallback)
    ]

    nmap_file = None
    for file in nmap_files:
        if file.exists() and file.stat().st_size > 0:
            nmap_file = file
            logger.info(f"[🔍] Lecture du fichier nmap: {file.name}")
            break

    if not nmap_file:
        logger.warning("[⚠️] Aucun fichier nmap trouvé pour détection HTTP")
        return http_services

    try:
        content = nmap_file.read_text(errors="ignore")
        logger.info(f"[🔍] Analyse de {len(content.split(chr(10)))} lignes pour détection HTTP")

        # Ports web à forcer même si service non identifié
        web_ports = {80, 443, 8000, 8008, 8080, 8081, 8088, 8180, 8443, 8888,
                    9000, 9001, 9090, 9443, 3000, 3001, 4000, 4200, 5000, 5001,
                    7000, 7001, 7080, 7443, 10000, 10443, 8765, 8764, 8889}

        # 🆕 PARSER XML si c'est un fichier XML (plus fiable)
        if nmap_file.suffix == '.xml':
            logger.info("[🔍] Parsing du fichier XML nmap...")
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(nmap_file)
                root = tree.getroot()

                for port_elem in root.findall('.//port'):
                    protocol = port_elem.get('protocol')
                    portid = port_elem.get('portid')
                    state_elem = port_elem.find('state')
                    service_elem = port_elem.find('service')

                    if protocol == 'tcp' and state_elem is not None and state_elem.get('state') == 'open':
                        port = int(portid)
                        service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                        product = service_elem.get('product', '') if service_elem is not None else ''
                        tunnel = service_elem.get('tunnel', '') if service_elem is not None else ''

                        is_http = False
                        scheme = "http"

                        # Détection HTTP par nom de service
                        if service_name in ['http', 'https', 'http-proxy', 'http-alt', 'ssl/http']:
                            is_http = True
                            scheme = "https" if service_name == "https" or tunnel == "ssl" else "http"

                        # Détection par port
                        if port in web_ports:
                            is_http = True

                        # Détection HTTPS
                        if port in [443, 8443, 9443, 10443] or tunnel == 'ssl':
                            scheme = "https"

                        if is_http:
                            http_services[port] = scheme
                            logger.info(f"[✅] XML - Service HTTP: {port}/tcp ({scheme}) - {service_name}")

                logger.info(f"[🌐] Parsing XML terminé: {len(http_services)} service(s) HTTP")
                return http_services  # Retourner immédiatement si XML réussi

            except Exception as e:
                logger.warning(f"[⚠️] Erreur parsing XML, fallback vers parsing texte: {e}")
                # Continuer avec le parsing texte ci-dessous

        # Parser le format texte (.nmap ou .txt)
        for line in content.split('\n'):
            # Regex plus flexible pour gérer différents formats nmap
            # Format: PORT/tcp   open   SERVICE   VERSION...
            match = re.match(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?', line)
            if match:
                port = int(match.group(1))
                service = match.group(2).lower()
                details = match.group(3).lower() if match.group(3) else ""

                # Combinaison service + details pour recherche
                full_text = f"{service} {details}"

                is_http = False
                scheme = "http"

                # 1. Services web connus
                if service in ['http', 'https', 'http-proxy', 'http-alt', 'ssl/http', 'https-alt', 'http-wmap']:
                    is_http = True
                    scheme = "https" if service == "https" or "ssl" in service else "http"
                    logger.info(f"[🌐] Service web détecté par nom: {port}/tcp ({service})")

                # 2. Mots-clés web dans détails (ÉTENDU)
                http_keywords = ['http', 'web', 'apache', 'nginx', 'iis', 'tomcat',
                                'node.js', 'express', 'flask', 'django', 'lighttpd',
                                'jetty', 'gunicorn', 'uvicorn', 'werkzeug', 'cherrypy',
                                'tornado', 'bottle', 'fastapi', 'kestrel', 'caddy',
                                'traefik', 'envoy', 'haproxy', 'varnish']
                if any(keyword in full_text for keyword in http_keywords):
                    is_http = True
                    logger.info(f"[🌐] Service web détecté par keyword: {port}/tcp")

                # 3. Ports web standards et non-standards (AUTO-INCLUDE)
                if port in web_ports:
                    is_http = True
                    logger.info(f"[🌐] Port web standard détecté: {port}/tcp")

                # 4. Détection HTTPS sur ports SSL
                if port in [443, 8443, 9443, 10443] or "ssl" in full_text or "tls" in full_text:
                    scheme = "https"

                # 5. Si le service est unknown/filtered/tcpwrapped mais port web connu, considérer comme HTTP
                if service in ["unknown", "filtered", "tcpwrapped"] and port in web_ports:
                    is_http = True
                    logger.info(f"[🌐] Service '{service}' sur port web {port} → Considéré comme HTTP")

                if is_http:
                    http_services[port] = scheme
                    logger.info(f"[✅] Service HTTP confirmé: {port}/tcp ({scheme})")

    except Exception as e:
        logger.error(f"[❌] Erreur détection HTTP: {e}")
        import traceback
        logger.debug(traceback.format_exc())

    logger.info(f"[🌐] Total services HTTP détectés: {len(http_services)}")

    # 🆕 FALLBACK ULTIME: Si aucun service HTTP détecté, forcer l'ajout des ports web communs
    if not http_services:
        logger.warning("[⚠️] Aucun service HTTP détecté via parsing nmap")
        logger.info("[🔍] Tentative de détection forcée des ports web communs ouverts...")

        # 🔍 DEBUG: Afficher quelques lignes du fichier pour diagnostic
        sample_lines = content.split('\n')[:10]
        logger.debug(f"[DEBUG] Premières lignes du fichier nmap:")
        for i, sample in enumerate(sample_lines, 1):
            logger.debug(f"  {i}: {sample[:100]}")

        # Chercher TOUS les ports ouverts (pas seulement les ports web)
        all_open_ports = set()
        for line in content.split('\n'):
            # Essayer plusieurs patterns pour détecter les ports ouverts
            patterns = [
                r'(\d+)/tcp\s+open',           # Format standard
                r'(\d+)/tcp.*open',            # Format avec espaces multiples
                r'Discovered open port (\d+)', # Format rustscan dans le même fichier
            ]

            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    all_open_ports.add(int(match.group(1)))
                    break

        logger.info(f"[🔍] Ports ouverts détectés dans le fichier: {sorted(all_open_ports)}")

        # Forcer l'ajout des ports web qui sont ouverts
        web_ports_extended = {80, 443, 8000, 8080, 8443, 8765, 8888, 3000, 5000, 9000}
        for port in all_open_ports:
            if port in web_ports_extended:
                scheme = "https" if port in {443, 8443, 9443, 10443} else "http"
                http_services[port] = scheme
                logger.info(f"[🌐] FALLBACK - Port web ajouté: {port}/tcp ({scheme})")

    return http_services

# ============================================================
# 🔍 RECONNAISSANCE DE BASE
# ============================================================
def basic_recon(target: str, base: Path):
    """Reconnaissance de base avec commandes système."""
    logger = logging.getLogger(__name__)
    recon = base / "scans" / "basic_recon"
    recon.mkdir(parents=True, exist_ok=True)

    logger.info("[🔍] Reconnaissance de base...")

    target_safe = shlex.quote(target)

    run(f"ping -c 4 {target_safe}", recon / "ping.txt", timeout=15)

    if tool_exists("traceroute"):
        run(f"traceroute -m 15 {target_safe}", recon / "traceroute.txt", timeout=60)
    else:
        run(f"tracepath {target_safe}", recon / "tracepath.txt", timeout=60)

    run(f"nslookup {target_safe}", recon / "nslookup.txt", timeout=10)

    if tool_exists("dig"):
        run(f"dig {target_safe} ANY", recon / "dig.txt", timeout=10)

    run(f"host {target_safe}", recon / "host.txt", timeout=10)
    run(f"arp -a | grep -i {target_safe}", recon / "arp.txt", timeout=5, allow_fail=True)

    if tool_exists("whois"):
        run(f"whois {target_safe}", recon / "whois.txt", timeout=15, allow_fail=True)
    
    run("ip route", recon / "routes.txt", timeout=5)
    run("ip addr show", recon / "interfaces.txt", timeout=5)

# ============================================================
# 🔎 SCAN CORE OPTIMISÉ
# ============================================================
def rustscan(target: str, base: Path) -> List[int]:
    """Scan rapide des ports avec rustscan + fallback intelligent."""
    logger = logging.getLogger(__name__)
    out = base / "scans" / "rustscan.txt"

    target_safe = shlex.quote(target)

    if not tool_exists("rustscan"):
        logger.warning("[⚠️] rustscan non trouvé, fallback vers nmap")
        run(f"nmap -p- --min-rate 1000 -T3 {target_safe}", out, timeout=900)
    else:
        # Premier essai : Rapide (batch 1000)
        logger.info("[⚡] Rustscan - Mode rapide (batch 1000)")
        run(f"rustscan -a {target_safe} --ulimit 5000 -b 1000 --no-config", out, timeout=600)

        # Vérifier si des ports ont été trouvés
        try:
            content = out.read_text(errors="ignore")
            initial_ports = len(re.findall(r"Open\s+.*:\d+", content))

            # Si aucun port trouvé ET pas d'erreur fatale
            if initial_ports == 0 and "Open" not in content:
                logger.warning("[⚠️] Aucun port détecté - Retry avec batch size réduit pour latence élevée")

                # Deuxième essai : Adapté latence élevée (batch 500 + timeout 2000ms)
                out_retry = base / "scans" / "rustscan_retry.txt"
                logger.info("[🐢] Rustscan - Mode latence élevée (batch 500, timeout 2s)")
                run(
                    f"rustscan -a {target_safe} --ulimit 2000 -b 500 -t 2000 --no-config",
                    out_retry,
                    timeout=900
                )

                # Si le retry a trouvé des ports, remplacer le fichier principal
                retry_content = out_retry.read_text(errors="ignore")
                retry_ports = len(re.findall(r"Open\s+.*:\d+", retry_content))

                if retry_ports > 0:
                    logger.info(f"[✅] Retry réussi ! {retry_ports} port(s) trouvé(s)")
                    # Copier les résultats du retry dans le fichier principal
                    out.write_text(retry_content)
                else:
                    logger.warning("[⚠️] Retry sans succès - Possible firewall ou cible inactive")
        except Exception as e:
            logger.error(f"[❌] Erreur vérification rustscan: {e}")

    # Parser les ports trouvés
    ports = set()
    try:
        content = out.read_text(errors="ignore")
        for m in re.finditer(r"Open\s+.*:(\d+)", content):
            ports.add(int(m.group(1)))
        for m in re.finditer(r"(\d+)/(tcp|udp)\s+open", content):
            ports.add(int(m.group(1)))
    except Exception as e:
        logger.error(f"[❌] Erreur parsing rustscan: {e}")

    logger.info(f"[✅] {len(ports)} ports détectés")
    return sorted(ports)

def nmap_tcp(target: str, ports: List[int], base: Path):
    """Scan TCP détaillé."""
    if not ports:
        return
    port_str = ','.join(map(str, ports[:100]))
    target_safe = shlex.quote(target)
    run(
        f"nmap -sC -sV -O -A -Pn -T3 --max-retries 2 -p {port_str} {target_safe} -oA {base/'scans/nmap_tcp'}",
        base / "scans" / "nmap_tcp.txt",
        timeout=1200
    )

def nmap_udp(target: str, base: Path, mode: str):
    """Scan UDP."""
    target_safe = shlex.quote(target)
    if mode == "fast":
        run(
            f"nmap -sU -p {UDP_FAST_PORTS} {target_safe}",
            base / "scans" / "nmap_udp.txt",
            timeout=600
        )
    else:
        run(
            f"nmap -sU --top-ports 100 {target_safe}",
            base / "scans" / "nmap_udp.txt",
            timeout=900
        )

# ============================================================
# 📡 DNS ENUMERATION
# ============================================================
def enum_dns(target: str, base: Path, domain: Optional[str] = None):
    """Énumération DNS complète."""
    logger = logging.getLogger(__name__)
    dns = base / "dns"

    target_safe = shlex.quote(target)

    if not domain:
        try:
            result = subprocess.run(
                f"host {target_safe}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                match = re.search(r'domain name pointer (.+)\.', result.stdout)
                if match:
                    domain = match.group(1)
                    logger.info(f"[🌐] Domaine détecté: {domain}")
        except:
            pass

    if domain:
        domain_safe = shlex.quote(domain)
        logger.info(f"[🌐] Test de zone transfer pour {domain}")
        run(f"dig @{target_safe} {domain_safe} AXFR", dns / "axfr.txt", timeout=30)

        if tool_exists("dnsrecon"):
            run(
                f"dnsrecon -d {domain_safe} -t brt -n {target_safe}",
                dns / "dnsrecon_brt.txt",
                timeout=300
            )

    if tool_exists("nmap"):
        run(
            f"nmap -sU -p53 --script dns-* {target_safe}",
            dns / "nmap_dns.txt",
            timeout=120
        )

# ============================================================
# 🌐 WEB ENUMERATION AMÉLIORÉE (GOBUSTER + DIRSEARCH)
# ============================================================
def enum_web_single_port(target: str, port: int, scheme: str, base: Path, mode: str,
                         username: Optional[str] = None, password: Optional[str] = None,
                         vpn_mode: bool = False, auto_hosts: bool = False):
    """Énumération web pour un port spécifique avec Gobuster (Dirsearch optionnel)."""
    logger = logging.getLogger(__name__)

    web = base / "web" / f"port_{port}"
    web.mkdir(parents=True, exist_ok=True)
    loot = base / "loot" / f"port_{port}"
    loot.mkdir(parents=True, exist_ok=True)

    url = f"{scheme}://{target}:{port}"
    logger.info(f"[🌐] Énumération web sur {url}")

    # 1. RECONNAISSANCE PRÉLIMINAIRE (Séquentiel pour détection de domaine)
    discovered_domain = None
    
    # Headers & Redirections
    run(f"curl -I -k -m 10 {url}", web / "headers.txt")
    try:
        content = (web / "headers.txt").read_text(errors="ignore")
        match = re.search(r'Location:\s*https?://([^/:]+)', content, re.IGNORECASE)
        if match:
            candidate = match.group(1)
            if candidate != target and not re.match(r"^\d+\.\d+\.\d+\.\d+$", candidate):
                discovered_domain = candidate
                logger.info(f"[🎯] Redirection détectée vers: {discovered_domain}")
    except Exception as e:
        logger.debug(f"[DEBUG] Erreur parsing headers: {e}")

    # Whatweb & Emails
    if tool_exists("whatweb"):
        run(f"whatweb -a 3 {url}", web / "whatweb.txt")
        try:
            content = (web / "whatweb.txt").read_text(errors="ignore")
            # Extraction email pour trouver le domaine (ex: info@facts.htb)
            emails = re.findall(r'[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})', content)
            for domain in emails:
                if domain != target and not re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
                    discovered_domain = domain
                    logger.info(f"[🎯] Domaine détecté via email: {discovered_domain}")
                    break
        except Exception as e:
            logger.debug(f"[DEBUG] Erreur parsing whatweb: {e}")

    # Mise à jour hosts et URL
    if discovered_domain:
        update_hosts_file(target, discovered_domain, auto_hosts)
        # Si le domaine pointe vers l'IP cible, on met à jour l'URL pour la suite des scans
        url = f"{scheme}://{discovered_domain}:{port}"
        logger.info(f"[🔄] Mise à jour de la cible scan: {url}")

    tasks = []
    
    # Nikto
    if tool_exists("nikto"):
        tasks.append(("nikto", lambda u=url, wb=web: run(
            f"nikto -h {u} -Tuning 123bde -timeout 3 -maxtime 180 -output {wb/'nikto.txt'}",
            timeout=200,
            allow_fail=True
        )))

    # Vhost fuzzing
    if port in [80, 443] and tool_exists("ffuf"):
        vhost_wordlist = None
        wordlists_to_try = VHOST_WORDLISTS[:1] if mode == "fast" else VHOST_WORDLISTS[:2]

        for wl in wordlists_to_try:
            if Path(wl).exists():
                vhost_wordlist = wl
                break

        if vhost_wordlist:
            tasks.append(("vhosts", lambda wl=vhost_wordlist, u=url, t=target, wb=web: run(
                f"ffuf -w {wl} -u {u} -H 'Host: FUZZ.{t}' "
                f"-t 50 -p 0.05-0.1 -ac -mc all -fc 404,400 "
                f"-o {wb/'vhosts.json'} -of json -s",
                wb / "vhosts.txt",
                timeout=300
            )))

    # Hakrawler
    if tool_exists("hakrawler"):
        tasks.append(("crawler", lambda u=url, wb=web: run(
            f"hakrawler -url {u} -depth 2 -plain -t 20",
            wb / "urls.txt",
            timeout=180
        )))

    # 🔥 OPTIMISATION VPN : Paramètres adaptatifs
    if vpn_mode:
        # Mode VPN-safe : réduit threads et augmente delays
        threads = 10  # Réduit de 40 à 10 pour éviter saturation
        delay = "200ms"  # Augmenté de 50ms à 200ms
        logger.info(f"[🔥] Mode VPN activé : threads={threads}, delay={delay}")
    else:
        # Mode normal (LAN/sans VPN)
        threads = 30  # Réduit de 40 à 30 (toujours raisonnable)
        delay = "100ms"  # Augmenté de 50ms à 100ms (plus stable)

    # 🆕 GOBUSTER (OUTIL PRINCIPAL - toujours utilisé)
    # Utilisation de directory-list-2.3-medium.txt par défaut (meilleurs résultats)
    wordlist = WORDLISTS.get("default", WORDLISTS.get("full", WORDLISTS["fast"]))
    if tool_exists("gobuster") and Path(wordlist).exists():
        logger.info(f"[📁] Gobuster sur {url} (threads={threads}, delay={delay})")

        wordlist_safe = shlex.quote(wordlist)
        url_safe = shlex.quote(url)

        # Options d'authentification
        auth_opts = ""
        if username and password:
            username_safe = shlex.quote(username)
            password_safe = shlex.quote(password)
            auth_opts = f"-U {username_safe} -P {password_safe}"
            logger.info(f"[🔐] Gobuster avec authentification: {username}")

        tasks.append(("gobuster", lambda u=url_safe, w=wordlist_safe, t=threads, d=delay, a=auth_opts, wb=web, m=mode: run(
            f"gobuster dir -u {u} -w {w} "
            f"-t {t} -k -x php,html,txt,js,bak,old,zip,tar,gz "
            f"-b 404 --delay {d} {a} "
            f"--no-error "  # Réduit le bruit et les erreurs
            f"-o {wb/'gobuster.txt'}",
            timeout=1200 if m == "full" else 900  # Augmenté pour compenser les delays
        )))

    # 🚫 DIRSEARCH DÉSACTIVÉ PAR DÉFAUT (redondant avec Gobuster)
    # Note: Dirsearch utilise la même wordlist et trouve généralement les mêmes résultats
    # que Gobuster. Pour éviter la saturation VPN, on ne l'utilise que si explicitement demandé.
    # Pour activer Dirsearch, décommenter le code ci-dessous :

    # if tool_exists("dirsearch") and Path(wordlist).exists() and mode == "full":
    #     logger.info(f"[🔍] Dirsearch sur {url} (complémentaire)")
    #     wordlist_safe = shlex.quote(wordlist)
    #     url_safe = shlex.quote(url)
    #     auth_opts = ""
    #     if username and password:
    #         username_safe = shlex.quote(username)
    #         password_safe = shlex.quote(password)
    #         auth_opts = f"--auth-type=basic --auth={username_safe}:{password_safe}"
    #     tasks.append(("dirsearch", lambda: run(
    #         f"dirsearch -u {url_safe} -w {wordlist_safe} "
    #         f"-t {threads} -e php,html,txt,js,bak,old,zip,tar,gz "
    #         f"--exclude-status=404,403 {auth_opts} "
    #         f"--delay={int(delay.replace('ms', '')) / 1000} "
    #         f"-o {web/'dirsearch.txt'} --format=plain",
    #         timeout=1200 if mode == "full" else 900
    #     )))

    # Exécution parallèle des scans
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(task[1]): task[0] for task in tasks}
        for future in as_completed(futures):
            task_name = futures[future]
            try:
                future.result()
                logger.info(f"[✅] {url} - {task_name} terminé")
            except Exception as e:
                logger.error(f"[❌] {url} - {task_name} échoué: {e}")

    # ⏸️ Attendre que tous les scans soient terminés avant de continuer
    logger.info(f"[⏳] Scans terminés, début du post-processing...")

    # 🆕 Analyse du code source HTML
    try:
        logger.info(f"[🔍] Analyse du code source HTML...")
        analyze_html_source(url, web, username, password)
    except Exception as e:
        logger.error(f"[❌] Erreur analyse HTML: {e}")

    # 🆕 POST-PROCESSING: Extraction des fichiers intéressants
    try:
        logger.info(f"[📥] Récupération des fichiers intéressants...")
        download_interesting_files(url, web, loot, username, password)
    except Exception as e:
        logger.error(f"[❌] Erreur téléchargement fichiers: {e}")

    # 🆕 Énumération récursive des sous-dossiers
    try:
        logger.info(f"[🔄] Énumération récursive des sous-dossiers...")
        enumerate_subdirectories(url, web, loot, mode, username, password, vpn_mode)
    except Exception as e:
        logger.error(f"[❌] Erreur énumération récursive: {e}")

    # 🆕 Génération du schéma d'arborescence
    try:
        logger.info(f"[🌳] Génération de l'arborescence...")
        build_directory_tree(web)
    except Exception as e:
        logger.error(f"[❌] Erreur génération arborescence: {e}")

    # Post-processing URLs
    urls_file = web / "urls.txt"
    if urls_file.exists() and tool_exists("uro"):
        run(
            f"cat {urls_file} | grep '?' | uro > {web/'fuzz_targets.txt'}",
            timeout=60,
            allow_fail=True
        )

def enumerate_subdirectories(base_url: str, web_dir: Path, loot_dir: Path, mode: str,
                            username: Optional[str] = None, password: Optional[str] = None,
                            vpn_mode: bool = False):
    """Énumère récursivement les sous-dossiers découverts."""
    logger = logging.getLogger(__name__)

    # Adaptation VPN pour énumération récursive
    if vpn_mode:
        threads = 8  # Encore plus conservateur pour récursif
        delay = "250ms"
        max_subdirs = 5  # Limite le nombre de sous-dossiers à scanner
    else:
        threads = 20
        delay = "150ms"
        max_subdirs = 10

    # Récupérer les dossiers (Status: 301/302) depuis gobuster/dirsearch
    directories = set()

    for result_file in ["gobuster.txt", "dirsearch.txt"]:
        file_path = web_dir / result_file
        if not file_path.exists():
            continue

        try:
            content = file_path.read_text(errors="ignore")

            # Gobuster format: /path (Status: 301)
            for match in re.finditer(r'(\/[^\s]+)\s+\(Status:\s*(301|302)', content):
                path = match.group(1).rstrip('/')
                directories.add(path)

            # Dirsearch format: 301 - /path
            for match in re.finditer(r'(301|302)\s+[-|]\s+(\/[^\s]+)', content):
                path = match.group(2).rstrip('/')
                directories.add(path)

        except Exception as e:
            logger.error(f"[❌] Erreur parsing {result_file}: {e}")

    if not directories:
        logger.info("[ℹ️] Aucun sous-dossier à énumérer")
        return

    logger.info(f"[📂] {len(directories)} sous-dossier(s) détecté(s)")

    # Limiter le nombre de sous-dossiers (adapté VPN)
    subdirs_to_scan = sorted(list(directories))[:max_subdirs]
    if vpn_mode:
        logger.info(f"[🔥] Mode VPN : limitation à {max_subdirs} sous-dossiers (threads={threads}, delay={delay})")

    # Wordlist rapide pour les sous-dossiers
    subdir_wordlist = WORDLISTS.get("fast")
    if not Path(subdir_wordlist).exists():
        logger.warning("[⚠️] Wordlist fast non trouvée, skip énumération récursive")
        return

    recursive_results = web_dir / "recursive_scan.txt"
    results_lines = [f"# Énumération récursive des sous-dossiers\n\n"]

    for subdir in subdirs_to_scan:
        subdir_url = f"{base_url}{subdir}"
        logger.info(f"[🔄] Scan de {subdir_url}")

        results_lines.append(f"## {subdir}\n\n")

        # Scan rapide avec gobuster
        if tool_exists("gobuster"):
            temp_output = web_dir / f"recursive_{subdir.replace('/', '_')}.txt"

            wordlist_safe = shlex.quote(subdir_wordlist)
            url_safe = shlex.quote(subdir_url)

            auth_opts = ""
            if username and password:
                username_safe = shlex.quote(username)
                password_safe = shlex.quote(password)
                auth_opts = f"-U {username_safe} -P {password_safe}"

            run(
                f"gobuster dir -u {url_safe} -w {wordlist_safe} "
                f"-t {threads} -k -x php,html,txt,js,bak,old "
                f"-b 404 --delay {delay} {auth_opts} "
                f"--no-error -o {temp_output} --quiet",
                timeout=180 if vpn_mode else 120,
                allow_fail=True
            )

            # Lire les résultats
            if temp_output.exists():
                subdir_content = temp_output.read_text(errors="ignore")
                if subdir_content.strip():
                    results_lines.append(f"```\n{subdir_content}\n```\n\n")

                    # Télécharger les fichiers intéressants trouvés dans ce sous-dossier
                    for line in subdir_content.split('\n'):
                        if any(ext in line.lower() for ext in ['.bak', '.old', '.txt', '.config', '.zip']):
                            match = re.search(r'(\/[^\s]+)\s+\(Status:\s*200', line)
                            if match:
                                file_path = match.group(1)
                                file_url = f"{base_url}{file_path}"
                                filename = file_path.split('/')[-1]
                                safe_filename = re.sub(r'[^\w\-_\.]', '_', filename)
                                output_file = loot_dir / safe_filename

                                curl_cmd = f"curl -k -m 30 -L -o {shlex.quote(str(output_file))} "
                                if username and password:
                                    curl_cmd += f"-u {shlex.quote(username)}:{shlex.quote(password)} "
                                curl_cmd += shlex.quote(file_url)

                                if run(curl_cmd, timeout=40, allow_fail=True):
                                    if output_file.exists() and output_file.stat().st_size > 0:
                                        logger.info(f"[✅] Récupéré: {file_path}")
                else:
                    results_lines.append("_Aucun résultat_\n\n")

    recursive_results.write_text(''.join(results_lines), encoding='utf-8')
    logger.info(f"[📄] Énumération récursive: {recursive_results}")

def build_directory_tree(web_dir: Path):
    """Construit un schéma d'arborescence des dossiers découverts."""
    logger = logging.getLogger(__name__)

    tree_file = web_dir / "directory_tree.txt"
    tree_lines = ["# 🌳 Arborescence du site web\n\n```\n"]

    # Parser gobuster et dirsearch pour construire l'arbre
    all_paths = {}  # {path: {status, size, type}}

    for result_file in ["gobuster.txt", "dirsearch.txt", "recursive_scan.txt"]:
        file_path = web_dir / result_file
        if not file_path.exists():
            continue

        try:
            content = file_path.read_text(errors="ignore")

            # Gobuster format
            for match in re.finditer(r'(\/[^\s]+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?', content):
                path = match.group(1)
                status = match.group(2)
                size = match.group(3) or "?"

                path_type = "📁" if status in ["301", "302"] else "📄"

                # Identifier les fichiers sensibles
                if any(ext in path.lower() for ext in ['.bak', '.old', '.config', '.sql', '.zip']):
                    path_type = "🔴"
                elif path.endswith('.js'):
                    path_type = "📜"
                elif path.endswith(('.php', '.asp', '.aspx', '.jsp')):
                    path_type = "🔧"

                all_paths[path] = {
                    'status': status,
                    'size': size,
                    'type': path_type
                }

        except Exception as e:
            logger.error(f"[❌] Erreur parsing {result_file}: {e}")

    if not all_paths:
        logger.info("[ℹ️] Aucun chemin pour construire l'arborescence")
        return

    # Construire l'arbre hiérarchique
    tree = {}
    for path in sorted(all_paths.keys()):
        parts = [p for p in path.split('/') if p]
        current = tree
        for part in parts:
            if part not in current:
                current[part] = {}
            current = current[part]

    # Fonction récursive pour afficher l'arbre
    def print_tree(node, prefix="", is_last=True, full_path="/"):
        items = list(node.items())
        for i, (name, subtree) in enumerate(items):
            is_last_item = (i == len(items) - 1)
            connector = "└── " if is_last_item else "├── "

            current_path = f"{full_path}{name}"
            if current_path in all_paths:
                info = all_paths[current_path]
                icon = info['type']
                status = info['status']
                size = info['size']
                tree_lines.append(f"{prefix}{connector}{icon} {name} ({status})")
                if size != "?":
                    tree_lines.append(f" [{size}B]")
                tree_lines.append("\n")
            else:
                # Dossier intermédiaire
                tree_lines.append(f"{prefix}{connector}📁 {name}/\n")

            # Récursion pour les sous-éléments
            if subtree:
                extension = "    " if is_last_item else "│   "
                print_tree(subtree, prefix + extension, is_last_item, f"{current_path}/")

    tree_lines.append("/\n")
    print_tree(tree)

    tree_lines.append("```\n\n")
    tree_lines.append("## 📊 Légende\n\n")
    tree_lines.append("- 📁 Dossier (301/302)\n")
    tree_lines.append("- 📄 Fichier standard (200)\n")
    tree_lines.append("- 🔴 Fichier sensible (.bak, .old, .config, .sql, .zip)\n")
    tree_lines.append("- 📜 JavaScript (.js)\n")
    tree_lines.append("- 🔧 Code serveur (.php, .asp, .jsp)\n")

    tree_file.write_text(''.join(tree_lines), encoding='utf-8')
    logger.info(f"[🌳] Arborescence générée: {tree_file}")

def analyze_html_source(url: str, web_dir: Path, username: Optional[str] = None,
                        password: Optional[str] = None):
    """Analyse le code source HTML pour extraire des informations sensibles."""
    logger = logging.getLogger(__name__)

    analysis_file = web_dir / "html_analysis.txt"
    findings = []

    # Télécharger la page source
    curl_cmd = f"curl -k -m 30 -L -s "
    if username and password:
        curl_cmd += f"-u {shlex.quote(username)}:{shlex.quote(password)} "
    curl_cmd += shlex.quote(url)

    try:
        result = subprocess.run(curl_cmd, shell=True, capture_output=True, text=True, timeout=40)
        if result.returncode != 0 or not result.stdout:
            return

        html = result.stdout
        findings.append(f"# Analyse du code source HTML - {url}\n\n")

        # 1. Commentaires HTML
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        if comments:
            findings.append(f"## 🔍 Commentaires HTML ({len(comments)} trouvés)\n\n")
            for i, comment in enumerate(comments[:15], 1):
                clean_comment = comment.strip()[:200]
                findings.append(f"{i}. {clean_comment}\n")
            findings.append("\n")

        # 2. Détection CMS
        cms_signatures = {
            'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/', r'wordpress'],
            'Joomla': [r'joomla', r'/components/', r'/administrator/'],
            'Drupal': [r'drupal', r'/sites/default/', r'/core/'],
            'Magento': [r'magento', r'/skin/frontend/'],
            'PrestaShop': [r'prestashop', r'/themes/'],
            'Django': [r'django', r'csrfmiddlewaretoken'],
            'Laravel': [r'laravel', r'X-CSRF-TOKEN'],
            'ASP.NET': [r'__VIEWSTATE', r'asp.net', r'WebResource.axd'],
        }

        detected_cms = []
        for cms, patterns in cms_signatures.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    detected_cms.append(cms)
                    break

        if detected_cms:
            findings.append(f"## 🎯 CMS/Framework détecté\n\n")
            for cms in detected_cms:
                findings.append(f"- **{cms}**\n")
            findings.append("\n")

        # 3. Chemins intéressants dans le code
        path_patterns = [
            r'(?:href|src|action)=["\']([^"\']+)["\']',
            r'(?:url|path|file):\s*["\']([^"\']+)["\']',
        ]

        discovered_paths = set()
        for pattern in path_patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                if any(ext in match.lower() for ext in ['.js', '.css', '.php', '.asp', '.json', '.xml', '.txt', '.bak']):
                    discovered_paths.add(match)

        if discovered_paths:
            findings.append(f"## 📁 Chemins découverts dans le code ({len(discovered_paths)} trouvés)\n\n")
            for path in sorted(list(discovered_paths)[:30]):
                findings.append(f"- {path}\n")
            findings.append("\n")

        # 4. Informations sensibles
        sensitive_patterns = {
            'Emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'API Keys': r'(?:api[_-]?key|apikey|access[_-]?token)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'Passwords': r'(?:password|passwd|pwd)[\s:=]+["\']([^"\']{3,})["\']',
            'Tokens': r'(?:token|secret|key)[\s:=]+["\']([a-zA-Z0-9_\-]{20,})["\']',
            'Internal IPs': r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b',
        }

        sensitive_found = False
        for category, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                if not sensitive_found:
                    findings.append(f"## ⚠️ Informations sensibles détectées\n\n")
                    sensitive_found = True
                findings.append(f"### {category}\n\n")
                for match in set(matches[:10]):
                    findings.append(f"- `{match}`\n")
                findings.append("\n")

        # 5. Meta tags intéressants
        meta_patterns = [
            r'<meta\s+name=["\']([^"\']+)["\']\s+content=["\']([^"\']+)["\']',
            r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']([^"\']+)["\']',
        ]

        meta_info = []
        for pattern in meta_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            meta_info.extend(matches)

        if meta_info:
            findings.append(f"## 📋 Meta Tags\n\n")
            for name, content in meta_info[:15]:
                findings.append(f"- **{name}**: {content[:100]}\n")
            findings.append("\n")

        # 6. JavaScript files
        js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html)
        if js_files:
            findings.append(f"## 📜 Fichiers JavaScript ({len(js_files)} trouvés)\n\n")
            for js in set(js_files[:20]):
                findings.append(f"- {js}\n")
            findings.append("\n")

        # 7. Formulaires et endpoints
        forms = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if forms:
            findings.append(f"## 📝 Formulaires détectés ({len(forms)} trouvés)\n\n")
            for form_action in set(forms):
                findings.append(f"- {form_action}\n")
            findings.append("\n")

        # Sauvegarder l'analyse
        if len(findings) > 1:  # Plus que juste le header
            analysis_file.write_text(''.join(findings), encoding='utf-8')
            logger.info(f"[🔍] Analyse HTML sauvegardée: {analysis_file}")
            return findings

    except Exception as e:
        logger.error(f"[❌] Erreur analyse HTML: {e}")

    return None

def download_interesting_files(base_url: str, web_dir: Path, loot_dir: Path,
                               username: Optional[str] = None, password: Optional[str] = None):
    """Télécharge automatiquement les fichiers intéressants découverts."""
    logger = logging.getLogger(__name__)

    # Extensions et patterns intéressants
    interesting_patterns = [
        r'\.bak\b', r'\.old\b', r'\.backup\b', r'\.config\b',
        r'\.sql\b', r'\.db\b', r'\.sqlite\b',
        r'\.log\b', r'\.txt\b', r'\.zip\b', r'\.tar\.gz\b',
        r'/users\.', r'/passwords\.', r'/credentials\.',
        r'/config\.', r'/backup\.', r'/database\.',
    ]

    discovered_paths = []

    # Parser les résultats de gobuster et dirsearch
    for result_file in ["gobuster.txt", "dirsearch.txt"]:
        file_path = web_dir / result_file
        if not file_path.exists():
            continue

        try:
            content = file_path.read_text(errors="ignore")

            # Gobuster format: /path (Status: 200)
            for line in content.split('\n'):
                for pattern in interesting_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Extraction du chemin
                        match = re.search(r'(\/[^\s]+)\s+\(Status:\s*(\d+)', line)
                        if match:
                            path = match.group(1)
                            status = match.group(2)
                            if status in ['200', '301', '302']:
                                discovered_paths.append(path)
                        # Dirsearch format: 200 - /path
                        match2 = re.search(r'(\d+)\s+[-|]\s+(\/[^\s]+)', line)
                        if match2:
                            status = match2.group(1)
                            path = match2.group(2)
                            if status in ['200', '301', '302']:
                                discovered_paths.append(path)
        except Exception as e:
            logger.error(f"[❌] Erreur parsing {result_file}: {e}")

    # Téléchargement des fichiers
    discovered_paths = list(set(discovered_paths))  # Dédupliquer

    if discovered_paths:
        logger.info(f"[💎] {len(discovered_paths)} fichier(s) intéressant(s) détecté(s)")

        # Créer un fichier récapitulatif
        summary_file = loot_dir / "discovered_files.txt"
        summary_lines = [f"# Fichiers intéressants découverts sur {base_url}\n\n"]

        for path in discovered_paths[:50]:  # Limite à 50 fichiers
            full_url = f"{base_url}{path}"
            filename = path.split('/')[-1] or 'index'
            safe_filename = re.sub(r'[^\w\-_\.]', '_', filename)
            output_file = loot_dir / safe_filename

            # Construire la commande curl
            curl_cmd = f"curl -k -m 30 -L -o {shlex.quote(str(output_file))} "

            if username and password:
                curl_cmd += f"-u {shlex.quote(username)}:{shlex.quote(password)} "

            curl_cmd += shlex.quote(full_url)

            # Télécharger
            success = run(curl_cmd, timeout=40, allow_fail=True)

            if success and output_file.exists() and output_file.stat().st_size > 0:
                logger.info(f"[✅] Téléchargé: {path} → {output_file.name}")
                summary_lines.append(f"✅ {full_url}\n   → {output_file}\n\n")
            else:
                logger.warning(f"[⚠️] Échec téléchargement: {path}")
                summary_lines.append(f"❌ {full_url}\n\n")

        summary_file.write_text(''.join(summary_lines), encoding='utf-8')
        logger.info(f"[📄] Résumé: {summary_file}")
    else:
        logger.info(f"[ℹ️] Aucun fichier intéressant détecté")

def enum_web(target: str, http_services: Dict[int, str], base: Path, mode: str,
             username: Optional[str] = None, password: Optional[str] = None,
             vpn_mode: bool = False, auto_hosts: bool = False):
    """Énumération web pour tous les ports HTTP détectés."""
    logger = logging.getLogger(__name__)

    if not http_services:
        logger.info("[🌐] Aucun service web détecté")
        return

    logger.info(f"[🌐] {len(http_services)} service(s) web détecté(s)")

    for port, scheme in sorted(http_services.items()):
        enum_web_single_port(target, port, scheme, base, mode, username, password, vpn_mode, auto_hosts)

# ============================================================
# 🧠 SMB CORE (AUTHENTIFIÉ + NXC HOSTS)
# ============================================================
def enum_smb(target: str, base: Path, username: Optional[str] = None,
             password: Optional[str] = None, domain: Optional[str] = None):
    """Énumération SMB/AD complète avec authentification."""
    logger = logging.getLogger(__name__)
    smb = base / "smb"

    target_safe = shlex.quote(target)
    tasks = []

    # 🆕 NETEXEC (NXC) avec génération /etc/hosts
    if tool_exists("netexec") or tool_exists("nxc"):
        nxc_cmd = "netexec" if tool_exists("netexec") else "nxc"

        # Sans authentification
        if not username or not password:
            logger.info("[🔐] NetExec - Scan anonyme")
            tasks.append(("nxc_shares", lambda: run(
                f"{nxc_cmd} smb {target_safe} --shares",
                smb / "nxc_shares_anon.txt",
                allow_fail=True
            )))

        # 🆕 Avec authentification
        else:
            logger.info(f"[🔐] NetExec - Authentification: {username}")

            username_safe = shlex.quote(username)
            password_safe = shlex.quote(password)
            auth_params = f"-u {username_safe} -p {password_safe}"
            if domain:
                domain_safe = shlex.quote(domain)
                auth_params += f" -d {domain_safe}"

            # Génération du fichier hosts
            hosts_file = smb / "nxc_hosts.txt"
            tasks.append(("nxc_hosts", lambda ap=auth_params: run(
                f"{nxc_cmd} smb {target_safe} {ap} --generate-hosts-file {hosts_file}",
                smb / "nxc_generate_hosts.txt",
                allow_fail=True
            )))

            # Énumération complète
            tasks.append(("nxc_shares_auth", lambda ap=auth_params: run(
                f"{nxc_cmd} smb {target_safe} {ap} --shares",
                smb / "nxc_shares_auth.txt",
                allow_fail=True
            )))

            tasks.append(("nxc_users", lambda ap=auth_params: run(
                f"{nxc_cmd} smb {target_safe} {ap} --users",
                smb / "nxc_users.txt",
                allow_fail=True
            )))

            tasks.append(("nxc_groups", lambda ap=auth_params: run(
                f"{nxc_cmd} smb {target_safe} {ap} --groups",
                smb / "nxc_groups.txt",
                allow_fail=True
            )))

            tasks.append(("nxc_pass_pol", lambda ap=auth_params: run(
                f"{nxc_cmd} smb {target_safe} {ap} --pass-pol",
                smb / "nxc_pass_policy.txt",
                allow_fail=True
            )))
    
    # 🆕 SMBMAP avec authentification
    if tool_exists("smbmap"):
        if username and password:
            logger.info(f"[🗺️] SMBMap - Authentification: {username}")

            username_safe = shlex.quote(username)
            password_safe = shlex.quote(password)
            smbmap_cmd = f"smbmap -H {target_safe} -u {username_safe} -p {password_safe}"
            if domain:
                domain_safe = shlex.quote(domain)
                smbmap_cmd += f" -d {domain_safe}"

            tasks.append(("smbmap_auth", lambda cmd=smbmap_cmd: run(
                cmd,
                smb / "smbmap_auth.txt",
                allow_fail=True
            )))

            # Récursif sur les shares
            tasks.append(("smbmap_recursive", lambda cmd=smbmap_cmd: run(
                f"{cmd} -R",
                smb / "smbmap_recursive.txt",
                timeout=300,
                allow_fail=True
            )))
        else:
            # Anonyme
            tasks.append(("smbmap_anon", lambda: run(
                f"smbmap -H {target_safe} -u '' -p ''",
                smb / "smbmap_anon.txt",
                allow_fail=True
            )))
    
    # Enum4linux
    if tool_exists("enum4linux-ng"):
        tasks.append(("enum4linux-ng", lambda: run(
            f"enum4linux-ng -A {target_safe} -oJ {smb/'enum4linux.json'}",
            smb / "enum4linux.txt",
            timeout=600
        )))
    elif tool_exists("enum4linux"):
        tasks.append(("enum4linux", lambda: run(
            f"enum4linux -a {target_safe}",
            smb / "enum4linux.txt",
            timeout=600
        )))

    # SMBClient
    if tool_exists("smbclient"):
        if username and password:
            username_safe = shlex.quote(username)
            password_safe = shlex.quote(password)
            creds = shlex.quote(f"{username}%{password}")
            tasks.append(("smbclient_auth", lambda c=creds: run(
                f"smbclient -L //{target_safe}/ -U {c}",
                smb / "smbclient_auth.txt",
                allow_fail=True
            )))
        else:
            tasks.append(("smbclient_anon", lambda: run(
                f"smbclient -L //{target_safe}/ -N",
                smb / "smbclient_anon.txt",
                allow_fail=True
            )))
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(task[1]): task[0] for task in tasks}
        for future in as_completed(futures):
            task_name = futures[future]
            try:
                future.result()
                logger.info(f"[✅] SMB/{task_name} terminé")
            except Exception as e:
                logger.error(f"[❌] SMB/{task_name} échoué: {e}")
    
    # 🆕 Avertissement pour mise à jour /etc/hosts
    hosts_file = smb / "nxc_hosts.txt"
    if hosts_file.exists():
        logger.info("\n" + "="*60)
        logger.info("🔥 NETEXEC - HOSTS FILE GÉNÉRÉ")
        logger.info("="*60)
        logger.info(f"📁 Fichier: {hosts_file}")
        logger.info("⚠️  Pour mettre à jour /etc/hosts:")
        logger.info(f"    sudo cat {hosts_file} >> /etc/hosts")
        logger.info("="*60 + "\n")

# ============================================================
# 📡 AUTRES PROTOCOLES
# ============================================================
def enum_ftp(target: str, base: Path):
    """Test FTP anonyme."""
    target_safe = shlex.quote(target)
    run(
        f"echo -e 'USER anonymous\\nPASS anonymous\\nPWD\\nLS -la\\nQUIT' | ftp -n {target_safe}",
        base / "ftp" / "ftp_anon.txt",
        timeout=30,
        allow_fail=True
    )

def enum_snmp(target: str, base: Path):
    """Énumération SNMP."""
    if not tool_exists("snmpwalk"):
        return

    target_safe = shlex.quote(target)
    communities = ["public", "private", "community"]
    for comm in communities:
        comm_safe = shlex.quote(comm)
        run(
            f"snmpwalk -v2c -c {comm_safe} {target_safe} 1.3.6.1",
            base / "snmp" / f"snmpwalk_{comm}.txt",
            timeout=300,
            allow_fail=True
        )

def enum_nfs(target: str, base: Path):
    """Énumération NFS."""
    target_safe = shlex.quote(target)
    if tool_exists("showmount"):
        run(f"showmount -e {target_safe}", base / "nfs" / "showmount.txt", allow_fail=True)

    if tool_exists("nmap"):
        run(
            f"nmap -p111,2049 --script nfs-* {target_safe}",
            base / "nfs" / "nmap_nfs.txt",
            timeout=120
        )

def enum_kerberos(target: str, base: Path):
    """Énumération Kerberos."""
    if tool_exists("nmap"):
        target_safe = shlex.quote(target)
        run(
            f"nmap -p88,464 --script krb5-enum-users {target_safe}",
            base / "kerberos" / "krb5_info.txt",
            timeout=120
        )

# ============================================================
# 🔎 SEARCHSPLOIT
# ============================================================
def enum_searchsploit(base: Path):
    """Recherche d'exploits."""
    nmap_file = base / "scans" / "nmap_tcp.xml"
    if nmap_file.exists() and tool_exists("searchsploit"):
        run(
            f"searchsploit --nmap {nmap_file}",
            base / "searchsploit" / "searchsploit.txt",
            timeout=60
        )

# ============================================================
# 📝 MODULES OPTIONNELS
# ============================================================
def enum_ad_full(target: str, base: Path, username: Optional[str] = None,
                 password: Optional[str] = None):
    """Énumération AD complète."""
    ad = base / "ad"

    if tool_exists("netexec") and username and password:
        target_safe = shlex.quote(target)
        username_safe = shlex.quote(username)
        password_safe = shlex.quote(password)
        auth = f"-u {username_safe} -p {password_safe}"
        run(f"netexec smb {target_safe} {auth} --users", ad / "users.txt", allow_fail=True)
        run(f"netexec smb {target_safe} {auth} --groups", ad / "groups.txt", allow_fail=True)
        run(f"netexec smb {target_safe} {auth} --pass-pol", ad / "pass_policy.txt", allow_fail=True)

def enum_web_aggressive(base: Path):
    """Fuzzing web agressif."""
    web = base / "web"
    
    for port_dir in web.glob("port_*"):
        fuzz_targets = port_dir / "fuzz_targets.txt"
        if fuzz_targets.exists() and tool_exists("nuclei"):
            run(
                f"nuclei -l {fuzz_targets} -o {port_dir/'nuclei.txt'}",
                timeout=1800,
                allow_fail=True
            )

def loot_mode(base: Path):
    """Recherche de credentials."""
    loot = base / "loot"
    patterns = ["password", "passwd", "pwd", "key", "credential", "secret", "token"]
    # Utiliser -E pour regex étendue, pas besoin d'échapper le pipe
    pattern_str = "|".join(patterns)
    base_safe = shlex.quote(str(base))

    run(
        f"grep -Erin {shlex.quote(pattern_str)} {base_safe} --exclude-dir=loot 2>/dev/null",
        loot / "interesting.txt",
        timeout=120,
        allow_fail=True
    )

# ============================================================
# 📊 PARSERS POUR EXTRACTION DE DONNÉES
# ============================================================
def parse_basic_recon(base: Path) -> Dict:
    """Parse les sorties de scans/basic_recon/*."""
    info = {
        "ping": {"alive": False, "ttl": 0, "avg_time": 0.0},
        "dns": {"hostname": "", "ips": []},
        "arp": {"mac": "", "vendor": ""},
        "traceroute": [],
        "whois": {"organization": "", "country": "", "inetnum": ""},
    }
    
    recon = base / "scans" / "basic_recon"
    if not recon.exists():
        return info
    
    ping_file = recon / "ping.txt"
    if ping_file.exists():
        content = ping_file.read_text(errors="ignore")
        if re.search(r"bytes from|ttl=", content, re.IGNORECASE):
            info["ping"]["alive"] = True
        ttl_m = re.search(r"ttl[=\s](\d+)", content, re.IGNORECASE)
        if ttl_m:
            info["ping"]["ttl"] = int(ttl_m.group(1))
    
    return info

def parse_nmap_services(base: Path) -> Dict:
    """Parse nmap services détaillés."""
    services = {}
    nmap_file = base / "scans" / "nmap_tcp.txt"
    
    if not nmap_file.exists():
        return services
    
    try:
        content = nmap_file.read_text(errors="ignore")
        for line in content.split('\n'):
            match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(.+)', line)
            if match:
                port = int(match.group(1))
                state = match.group(3)
                service_info = match.group(4)
                
                services[port] = {
                    'state': state,
                    'service': service_info,
                    'service_name': service_info.split()[0] if service_info else 'unknown'
                }
    except Exception as e:
        logging.getLogger(__name__).error(f"Erreur parsing nmap: {e}")
    
    return services

# ============================================================
# 📊 EXPORT MARKDOWN REPORT
# ============================================================
def export_markdown_report(target: str, ports: List[int], http_services: Dict[int, str],
                          base: Path, mode: str, findings: Dict, report_level: str = "summary",
                          username: Optional[str] = None, domain: Optional[str] = None):
    """
    Génère un rapport Markdown détaillé avec tous les résultats des scans.
    report_level: 'summary' (résumé intelligent) ou 'full' (tous les détails)
    """
    logger = logging.getLogger(__name__)

    # Parse des données
    basic_info = parse_basic_recon(base)
    services = parse_nmap_services(base)

    # Construction du rapport Markdown
    md_content = []

    # En-tête
    md_content.append(f"# 🦊 ReSCI ENUM REPORT - {target}\n")
    md_content.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    md_content.append(f"**Framework:** ReSCI v11.0\n")
    md_content.append("---\n\n")

    # Résumé exécutif
    md_content.append("## 📋 Résumé Exécutif\n\n")
    md_content.append(f"- **Cible**: `{target}`\n")
    md_content.append(f"- **Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    md_content.append(f"- **Durée**: {findings.get('duration', 'N/A')}\n")
    md_content.append(f"- **Mode**: {mode.upper()}\n")
    md_content.append(f"- **Ports ouverts**: {len(ports)}\n")
    md_content.append(f"- **Services web**: {len(http_services)}\n")
    if username:
        md_content.append(f"- **Authentification**: {username}@{domain or target}\n")
    md_content.append("\n---\n\n")

    # Reconnaissance de base
    md_content.append("## 🔍 Reconnaissance\n\n")

    # Ping
    md_content.append("### Connectivité (Ping)\n")
    if basic_info['ping']['alive']:
        ttl = basic_info['ping']['ttl']
        os_guess = "Linux/Unix" if 50 <= ttl <= 64 else "Windows" if 110 <= ttl <= 128 else "Unknown"
        md_content.append(f"✅ **Statut**: Actif  \n")
        md_content.append(f"📊 **TTL**: {ttl} (OS probable: {os_guess})\n\n")
    else:
        md_content.append("❌ **Statut**: Injoignable\n\n")

    # Fichier ping complet si mode full
    ping_file = base / "scans" / "basic_recon" / "ping.txt"
    if report_level == "full" and ping_file.exists():
        md_content.append("<details>\n<summary>📄 Résultat complet du ping</summary>\n\n")
        md_content.append("```\n")
        md_content.append(ping_file.read_text(errors="ignore")[:1000])
        md_content.append("\n```\n</details>\n\n")

    # DNS
    md_content.append("### DNS\n")
    if basic_info['dns']['hostname']:
        md_content.append(f"- **Hostname**: {basic_info['dns']['hostname']}\n")
    else:
        md_content.append("- **Hostname**: Non résolu\n")

    # Fichiers DNS
    dns_dir = base / "dns"
    if dns_dir.exists():
        for dns_file in ["axfr.txt", "dnsrecon_brt.txt", "nmap_dns.txt"]:
            file_path = dns_dir / dns_file
            if file_path.exists() and file_path.stat().st_size > 0:
                md_content.append(f"\n#### 🔍 {dns_file.replace('.txt', '').upper()}\n")
                content = file_path.read_text(errors="ignore")
                if report_level == "full":
                    md_content.append("<details>\n<summary>Voir le résultat</summary>\n\n```\n")
                    md_content.append(content[:5000])
                    md_content.append("\n```\n</details>\n\n")
                else:
                    lines = content.split('\n')[:20]
                    md_content.append("```\n")
                    md_content.append('\n'.join(lines))
                    md_content.append("\n```\n")
                    if len(content.split('\n')) > 20:
                        md_content.append(f"*...et {len(content.split('\n')) - 20} lignes supplémentaires*\n\n")

    md_content.append("\n---\n\n")

    # Ports & Services
    md_content.append("## 📊 Ports & Services\n\n")
    md_content.append(f"**Total des ports ouverts**: {len(ports)}\n\n")

    if services:
        md_content.append("### Tableau récapitulatif\n\n")
        md_content.append("| Port | État | Service | Détails |\n")
        md_content.append("|------|------|---------|----------|\n")
        for port, info in sorted(services.items())[:50]:
            service_short = info['service'][:60] + "..." if len(info['service']) > 60 else info['service']
            md_content.append(f"| {port} | {info['state']} | {info['service_name']} | {service_short} |\n")
        md_content.append("\n")

    # Nmap TCP complet
    nmap_tcp_file = base / "scans" / "nmap_tcp.txt"
    if nmap_tcp_file.exists():
        md_content.append("### 🔎 Scan Nmap TCP détaillé\n\n")
        content = nmap_tcp_file.read_text(errors="ignore")
        if report_level == "full":
            md_content.append("<details>\n<summary>Voir le résultat complet</summary>\n\n```\n")
            md_content.append(content)
            md_content.append("\n```\n</details>\n\n")
        else:
            lines = content.split('\n')[:50]
            md_content.append("```\n")
            md_content.append('\n'.join(lines))
            md_content.append("\n```\n")
            if len(content.split('\n')) > 50:
                md_content.append(f"*...et {len(content.split('\n')) - 50} lignes supplémentaires*\n\n")

    # Nmap UDP
    nmap_udp_file = base / "scans" / "nmap_udp.txt"
    if nmap_udp_file.exists() and nmap_udp_file.stat().st_size > 0:
        md_content.append("### 📡 Scan Nmap UDP\n\n")
        content = nmap_udp_file.read_text(errors="ignore")
        md_content.append("<details>\n<summary>Voir le résultat</summary>\n\n```\n")
        md_content.append(content[:3000] if report_level == "summary" else content)
        md_content.append("\n```\n</details>\n\n")

    md_content.append("\n---\n\n")

    # Services Web
    if http_services:
        md_content.append(f"## 🌐 Services Web ({len(http_services)})\n\n")

        for port, scheme in sorted(http_services.items()):
            url = f"{scheme}://{target}:{port}"
            md_content.append(f"### Port {port} - {scheme.upper()}\n\n")
            md_content.append(f"**URL**: [{url}]({url})\n\n")

            port_dir = base / "web" / f"port_{port}"
            if port_dir.exists():
                # Headers
                headers_file = port_dir / "headers.txt"
                if headers_file.exists():
                    md_content.append("#### 📋 Headers HTTP\n")
                    md_content.append("```http\n")
                    md_content.append(headers_file.read_text(errors="ignore")[:1000])
                    md_content.append("\n```\n\n")

                # Whatweb
                whatweb_file = port_dir / "whatweb.txt"
                if whatweb_file.exists():
                    md_content.append("#### 🔍 Whatweb\n")
                    md_content.append("```\n")
                    md_content.append(whatweb_file.read_text(errors="ignore")[:800])
                    md_content.append("\n```\n\n")

                # 🆕 Gobuster (prioritaire)
                gobuster_file = port_dir / "gobuster.txt"
                if gobuster_file.exists() and gobuster_file.stat().st_size > 0:
                    md_content.append("#### 📁 Gobuster - Énumération de répertoires\n\n")
                    content = gobuster_file.read_text(errors="ignore")

                    # Extraction des chemins intéressants
                    interesting_paths = []
                    for line in content.split('\n'):
                        if 'Status:' in line and any(ext in line.lower() for ext in ['.bak', '.old', '.txt', '.zip', '.config', 'users', 'admin']):
                            interesting_paths.append(line.strip())

                    if interesting_paths:
                        md_content.append("**🎯 Chemins critiques identifiés:**\n\n")
                        for path_line in interesting_paths[:20]:
                            md_content.append(f"- `{path_line}`\n")
                        md_content.append("\n")

                    if report_level == "full":
                        md_content.append("<details>\n<summary>Voir tous les résultats Gobuster</summary>\n\n```\n")
                        md_content.append(content)
                        md_content.append("\n```\n</details>\n\n")
                    else:
                        lines = content.split('\n')[:40]
                        md_content.append("<details>\n<summary>Top 40 résultats</summary>\n\n```\n")
                        md_content.append('\n'.join(lines))
                        md_content.append("\n```\n</details>\n\n")

                # 🆕 Dirsearch (complémentaire)
                dirsearch_file = port_dir / "dirsearch.txt"
                if dirsearch_file.exists() and dirsearch_file.stat().st_size > 0:
                    md_content.append("#### 🔍 Dirsearch - Énumération complémentaire\n\n")
                    content = dirsearch_file.read_text(errors="ignore")

                    # Extraction des chemins intéressants
                    interesting_paths = []
                    for line in content.split('\n'):
                        if any(ext in line.lower() for ext in ['.bak', '.old', '.txt', '.zip', '.config', 'users', 'admin']):
                            interesting_paths.append(line.strip())

                    if interesting_paths:
                        md_content.append("**🎯 Chemins critiques (Dirsearch):**\n\n")
                        for path_line in interesting_paths[:20]:
                            md_content.append(f"- `{path_line}`\n")
                        md_content.append("\n")

                    if report_level == "full":
                        md_content.append("<details>\n<summary>Voir tous les résultats Dirsearch</summary>\n\n```\n")
                        md_content.append(content)
                        md_content.append("\n```\n</details>\n\n")
                    else:
                        lines = content.split('\n')[:40]
                        md_content.append("<details>\n<summary>Top 40 résultats</summary>\n\n```\n")
                        md_content.append('\n'.join(lines))
                        md_content.append("\n```\n</details>\n\n")

                # 🆕 Arborescence du site
                tree_file = port_dir / "directory_tree.txt"
                if tree_file.exists():
                    md_content.append("#### 🌳 Arborescence du site web\n\n")
                    tree_content = tree_file.read_text(errors="ignore")
                    md_content.append(tree_content)
                    md_content.append("\n")

                # 🆕 Analyse du code source HTML
                html_analysis_file = port_dir / "html_analysis.txt"
                if html_analysis_file.exists():
                    md_content.append("#### 🔍 Analyse du code source HTML\n\n")
                    html_content = html_analysis_file.read_text(errors="ignore")

                    if report_level == "full":
                        md_content.append(html_content)
                    else:
                        # Extraire uniquement les sections importantes en mode summary
                        lines = html_content.split('\n')
                        important_sections = []
                        in_section = False
                        for line in lines:
                            if line.startswith('## '):
                                in_section = True
                                important_sections.append(line + '\n')
                            elif in_section and (line.startswith('###') or line.startswith('-')):
                                important_sections.append(line + '\n')
                            elif line.strip() == '':
                                in_section = False

                        md_content.append(''.join(important_sections[:500]) if important_sections else html_content[:1000])
                    md_content.append("\n")

                # 🆕 Énumération récursive
                recursive_file = port_dir / "recursive_scan.txt"
                if recursive_file.exists():
                    md_content.append("#### 🔄 Énumération récursive des sous-dossiers\n\n")
                    recursive_content = recursive_file.read_text(errors="ignore")

                    if report_level == "full":
                        md_content.append(recursive_content)
                    else:
                        # Top 20 lignes par sous-dossier en mode summary
                        md_content.append("<details>\n<summary>Voir les résultats de l'énumération récursive</summary>\n\n")
                        md_content.append(recursive_content[:2000])
                        md_content.append("\n</details>\n\n")

                # 🆕 Fichiers téléchargés
                loot_port_dir = base / "loot" / f"port_{port}"
                if loot_port_dir.exists():
                    discovered_file = loot_port_dir / "discovered_files.txt"
                    if discovered_file.exists():
                        md_content.append("#### 💎 Fichiers intéressants récupérés\n\n")
                        loot_content = discovered_file.read_text(errors="ignore")
                        md_content.append("```\n")
                        md_content.append(loot_content[:3000] if report_level == "summary" else loot_content)
                        md_content.append("\n```\n\n")

                        # Liste des fichiers téléchargés
                        downloaded_files = [f for f in loot_port_dir.glob("*") if f.is_file() and f.name != "discovered_files.txt"]
                        if downloaded_files:
                            md_content.append("**📥 Fichiers locaux:**\n\n")
                            for file in downloaded_files[:30]:
                                file_size = file.stat().st_size
                                md_content.append(f"- `{file.name}` ({file_size} bytes) - [{file}](file://{file})\n")
                            md_content.append("\n")

                # Nikto
                nikto_file = port_dir / "nikto.txt"
                if nikto_file.exists() and nikto_file.stat().st_size > 0:
                    md_content.append("#### 🛡️ Nikto - Scan de vulnérabilités\n")
                    content = nikto_file.read_text(errors="ignore")
                    md_content.append("<details>\n<summary>Voir le rapport Nikto</summary>\n\n```\n")
                    md_content.append(content[:5000] if report_level == "summary" else content)
                    md_content.append("\n```\n</details>\n\n")

                # VHosts
                vhosts_file = port_dir / "vhosts.txt"
                if vhosts_file.exists() and vhosts_file.stat().st_size > 0:
                    md_content.append("#### 🌍 Virtual Hosts découverts\n")
                    md_content.append("```\n")
                    md_content.append(vhosts_file.read_text(errors="ignore")[:1500])
                    md_content.append("\n```\n\n")

    md_content.append("\n---\n\n")

    # SMB / Active Directory
    smb_dir = base / "smb"
    if smb_dir.exists() and any(smb_dir.iterdir()):
        md_content.append("## 🧠 SMB / Active Directory\n\n")

        # NetExec shares
        for nxc_file in ["nxc_shares_auth.txt", "nxc_shares_anon.txt"]:
            file_path = smb_dir / nxc_file
            if file_path.exists() and file_path.stat().st_size > 0:
                md_content.append(f"### 📂 NetExec - Partages SMB\n")
                md_content.append("```\n")
                md_content.append(file_path.read_text(errors="ignore")[:3000])
                md_content.append("\n```\n\n")
                break

        # NetExec users
        nxc_users = smb_dir / "nxc_users.txt"
        if nxc_users.exists() and nxc_users.stat().st_size > 0:
            md_content.append("### 👥 Utilisateurs énumérés\n")
            md_content.append("```\n")
            md_content.append(nxc_users.read_text(errors="ignore"))
            md_content.append("\n```\n\n")

        # NetExec groups
        nxc_groups = smb_dir / "nxc_groups.txt"
        if nxc_groups.exists() and nxc_groups.stat().st_size > 0:
            md_content.append("### 👥 Groupes énumérés\n")
            md_content.append("```\n")
            md_content.append(nxc_groups.read_text(errors="ignore"))
            md_content.append("\n```\n\n")

        # Password policy
        pass_pol = smb_dir / "nxc_pass_policy.txt"
        if pass_pol.exists() and pass_pol.stat().st_size > 0:
            md_content.append("### 🔐 Politique de mots de passe\n")
            md_content.append("```\n")
            md_content.append(pass_pol.read_text(errors="ignore"))
            md_content.append("\n```\n\n")

        # SMBMap
        smbmap_files = ["smbmap_auth.txt", "smbmap_recursive.txt", "smbmap_anon.txt"]
        for smbmap_file in smbmap_files:
            file_path = smb_dir / smbmap_file
            if file_path.exists() and file_path.stat().st_size > 0:
                md_content.append(f"### 🗺️ SMBMap - {smbmap_file.replace('.txt', '').replace('_', ' ').title()}\n")
                content = file_path.read_text(errors="ignore")
                if report_level == "full":
                    md_content.append("<details>\n<summary>Voir le résultat complet</summary>\n\n```\n")
                    md_content.append(content)
                    md_content.append("\n```\n</details>\n\n")
                else:
                    md_content.append("```\n")
                    md_content.append(content[:2000])
                    md_content.append("\n```\n\n")

        # Enum4linux
        enum4linux_file = smb_dir / "enum4linux.txt"
        if enum4linux_file.exists() and enum4linux_file.stat().st_size > 0:
            md_content.append("### 📋 Enum4linux\n")
            content = enum4linux_file.read_text(errors="ignore")
            md_content.append("<details>\n<summary>Voir le résultat complet</summary>\n\n```\n")
            md_content.append(content[:10000] if report_level == "summary" else content)
            md_content.append("\n```\n</details>\n\n")

        # Hosts file reminder
        hosts_file = smb_dir / "nxc_hosts.txt"
        if hosts_file.exists():
            md_content.append("### ⚠️ Fichier /etc/hosts généré\n\n")
            md_content.append(f"**Fichier**: `{hosts_file}`\n\n")
            md_content.append("**Pour mettre à jour /etc/hosts:**\n")
            md_content.append(f"```bash\nsudo cat {hosts_file} >> /etc/hosts\n```\n\n")
            md_content.append("**Contenu:**\n```\n")
            md_content.append(hosts_file.read_text(errors="ignore"))
            md_content.append("\n```\n\n")

    md_content.append("\n---\n\n")

    # Autres services
    other_services = []

    # FTP
    ftp_file = base / "ftp" / "ftp_anon.txt"
    if ftp_file.exists() and ftp_file.stat().st_size > 0:
        other_services.append(("FTP", ftp_file))

    # SNMP
    snmp_dir = base / "snmp"
    if snmp_dir.exists():
        for snmp_file in snmp_dir.glob("*.txt"):
            if snmp_file.stat().st_size > 0:
                other_services.append((f"SNMP ({snmp_file.name})", snmp_file))

    # NFS
    nfs_dir = base / "nfs"
    if nfs_dir.exists():
        for nfs_file in nfs_dir.glob("*.txt"):
            if nfs_file.stat().st_size > 0:
                other_services.append((f"NFS ({nfs_file.name})", nfs_file))

    # Kerberos
    kerb_file = base / "kerberos" / "krb5_info.txt"
    if kerb_file.exists() and kerb_file.stat().st_size > 0:
        other_services.append(("Kerberos", kerb_file))

    if other_services:
        md_content.append("## 📡 Autres Services\n\n")
        for service_name, service_file in other_services:
            md_content.append(f"### {service_name}\n")
            md_content.append("```\n")
            content = service_file.read_text(errors="ignore")
            md_content.append(content[:1500] if report_level == "summary" else content)
            md_content.append("\n```\n\n")

    # Vecteurs d'attaque
    if findings.get('vectors'):
        md_content.append("\n---\n\n")
        md_content.append("## 🎯 Vecteurs d'Attaque Identifiés\n\n")
        for vector in findings['vectors']:
            md_content.append(f"### {vector['emoji']} {vector['title']}\n\n")
            md_content.append(f"{vector['description']}\n\n")

    # Searchsploit
    searchsploit_file = base / "searchsploit" / "searchsploit.txt"
    if searchsploit_file.exists() and searchsploit_file.stat().st_size > 0:
        md_content.append("\n---\n\n")
        md_content.append("## 🔍 Exploits potentiels (Searchsploit)\n\n")
        md_content.append("```\n")
        md_content.append(searchsploit_file.read_text(errors="ignore"))
        md_content.append("\n```\n\n")

    # Loot
    loot_file = base / "loot" / "interesting.txt"
    if loot_file.exists() and loot_file.stat().st_size > 0:
        md_content.append("\n---\n\n")
        md_content.append("## 💎 Loot - Informations sensibles\n\n")
        md_content.append("```\n")
        md_content.append(loot_file.read_text(errors="ignore")[:5000])
        md_content.append("\n```\n\n")

    # Footer
    md_content.append("\n---\n\n")
    md_content.append(f"**🦊 ReSCI ENUM Framework v10.0**  \n")
    md_content.append(f"**Généré le**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
    md_content.append(f"**Répertoire**: `{base}`  \n\n")
    md_content.append("⚠️ **CADRE LÉGAL**: Exploitation uniquement sous ROE/NDA valide\n")

    # Sauvegarder le rapport
    report_file = base / "exports" / f"REPORT_{mode.upper()}.md"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(''.join(md_content), encoding='utf-8')

    logger.info(f"[📄] Rapport Markdown généré: {report_file}")

    return report_file

# ============================================================
# 📊 EXPORT NOTION
# ============================================================
def export_notion_json(target: str, ports: List[int], http_services: Dict[int, str],
                      base: Path, mode: str, findings: Dict,
                      username: Optional[str] = None, domain: Optional[str] = None):
    """
    Génère un fichier JSON formaté pour import Notion.
    Compatible avec l'API Notion v2023-11-01
    """
    logger = logging.getLogger(__name__)
    
    # Parse des données
    basic_info = parse_basic_recon(base)
    services = parse_nmap_services(base)
    
    # Construction du rapport Notion
    notion_data = {
        "object": "page",
        "properties": {
            "Title": {
                "title": [
                    {
                        "text": {
                            "content": f"🦊 ReSCI - {target}"
                        }
                    }
                ]
            },
            "Target": {
                "rich_text": [
                    {
                        "text": {
                            "content": target
                        }
                    }
                ]
            },
            "Date": {
                "date": {
                    "start": datetime.now().isoformat()
                }
            },
            "Status": {
                "select": {
                    "name": "✅ Completed"
                }
            },
            "Severity": {
                "select": {
                    "name": "🔍 Enumeration"
                }
            }
        },
        "children": []
    }
    
    # 🎯 Résumé exécutif
    notion_data["children"].append({
        "object": "block",
        "type": "heading_1",
        "heading_1": {
            "rich_text": [{"text": {"content": "🎯 Résumé Exécutif"}}]
        }
    })
    
    summary_items = [
        f"**Cible** : `{target}`",
        f"**Date** : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Durée** : {findings.get('duration', 'N/A')}",
        f"**Mode** : {mode.upper()}",
        f"**Ports ouverts** : {len(ports)}",
        f"**Services web** : {len(http_services)}",
    ]
    
    if username:
        summary_items.append(f"**Authentification** : {username}@{domain or target}")
    
    for item in summary_items:
        notion_data["children"].append({
            "object": "block",
            "type": "paragraph",
            "paragraph": {
                "rich_text": [{"text": {"content": item}}]
            }
        })
    
    # 🔍 Reconnaissance
    notion_data["children"].append({
        "object": "block",
        "type": "heading_1",
        "heading_1": {
            "rich_text": [{"text": {"content": "🔍 Reconnaissance"}}]
        }
    })
    
    # Tableau de connectivité
    notion_data["children"].append({
        "object": "block",
        "type": "table",
        "table": {
            "table_width": 3,
            "has_column_header": True,
            "has_row_header": False,
            "children": [
                {
                    "object": "block",
                    "type": "table_row",
                    "table_row": {
                        "cells": [
                            [{"text": {"content": "Test"}}],
                            [{"text": {"content": "Résultat"}}],
                            [{"text": {"content": "Détails"}}]
                        ]
                    }
                },
                {
                    "object": "block",
                    "type": "table_row",
                    "table_row": {
                        "cells": [
                            [{"text": {"content": "Ping"}}],
                            [{"text": {"content": "✅ Actif" if basic_info['ping']['alive'] else "❌ Injoignable"}}],
                            [{"text": {"content": f"TTL: {basic_info['ping']['ttl']}"}}]
                        ]
                    }
                },
                {
                    "object": "block",
                    "type": "table_row",
                    "table_row": {
                        "cells": [
                            [{"text": {"content": "DNS"}}],
                            [{"text": {"content": basic_info['dns']['hostname'] or "Non résolu"}}],
                            [{"text": {"content": ', '.join(basic_info['dns']['ips'][:3]) if basic_info['dns']['ips'] else 'N/A'}}]
                        ]
                    }
                }
            ]
        }
    })
    
    # 📊 Ports & Services
    notion_data["children"].append({
        "object": "block",
        "type": "heading_1",
        "heading_1": {
            "rich_text": [{"text": {"content": "📊 Ports & Services"}}]
        }
    })
    
    # Top 20 services
    for port, info in sorted(services.items())[:20]:
        notion_data["children"].append({
            "object": "block",
            "type": "toggle",
            "toggle": {
                "rich_text": [{"text": {"content": f"🔌 Port {port}/TCP - {info['service_name']}"}}],
                "children": [
                    {
                        "object": "block",
                        "type": "paragraph",
                        "paragraph": {
                            "rich_text": [{"text": {"content": f"État: {info['state']}"}}]
                        }
                    },
                    {
                        "object": "block",
                        "type": "code",
                        "code": {
                            "language": "plain text",
                            "rich_text": [{"text": {"content": info['service'][:500]}}]
                        }
                    }
                ]
            }
        })
    
    # 🌐 Services Web
    if http_services:
        notion_data["children"].append({
            "object": "block",
            "type": "heading_1",
            "heading_1": {
                "rich_text": [{"text": {"content": f"🌐 Services Web ({len(http_services)})"}}]
            }
        })
        
        for port, scheme in sorted(http_services.items()):
            url = f"{scheme}://{target}:{port}"
            
            # Lire Feroxbuster/Gobuster results
            port_dir = base / "web" / f"port_{port}"
            endpoints = []
            
            if port_dir.exists():
                for result_file in ["feroxbuster.txt", "gobuster.txt"]:
                    result_path = port_dir / result_file
                    if result_path.exists():
                        content = result_path.read_text(errors="ignore")
                        # Extraire les endpoints (Status: 200, 301, etc.)
                        for line in content.split('\n')[:15]:
                            if 'Status:' in line or 'http' in line.lower():
                                endpoints.append(line.strip())
            
            web_children = [
                {
                    "object": "block",
                    "type": "paragraph",
                    "paragraph": {
                        "rich_text": [{"text": {"content": f"**URL** : {url}", "link": {"url": url}}}]
                    }
                }
            ]
            
            if endpoints:
                web_children.append({
                    "object": "block",
                    "type": "heading_3",
                    "heading_3": {
                        "rich_text": [{"text": {"content": "Endpoints découverts"}}]
                    }
                })
                web_children.append({
                    "object": "block",
                    "type": "code",
                    "code": {
                        "language": "plain text",
                        "rich_text": [{"text": {"content": '\n'.join(endpoints[:10])}}]
                    }
                })
            
            notion_data["children"].append({
                "object": "block",
                "type": "toggle",
                "toggle": {
                    "rich_text": [{"text": {"content": f"🌐 Port {port} - {scheme.upper()}"}}],
                    "children": web_children
                }
            })
    
    # 🎯 Vecteurs d'attaque
    if findings.get('vectors'):
        notion_data["children"].append({
            "object": "block",
            "type": "heading_1",
            "heading_1": {
                "rich_text": [{"text": {"content": "🎯 Vecteurs d'Attaque"}}]
            }
        })
        
        for vector in findings['vectors']:
            notion_data["children"].append({
                "object": "block",
                "type": "callout",
                "callout": {
                    "icon": {"emoji": vector['emoji']},
                    "rich_text": [{"text": {"content": f"{vector['title']}\n{vector['description']}"}}]
                }
            })
    
    # 📁 Structure fichiers
    notion_data["children"].append({
        "object": "block",
        "type": "heading_1",
        "heading_1": {
            "rich_text": [{"text": {"content": "📁 Structure des Fichiers"}}]
        }
    })
    
    file_structure = f"""
{base.name}/
├── scans/
│   ├── basic_recon/     # Reconnaissance système
│   ├── rustscan.txt     # Scan initial
│   ├── nmap_tcp.txt     # TCP détaillé
│   └── nmap_udp.txt     # UDP
├── web/
│   ├── port_80/         # HTTP
│   ├── port_443/        # HTTPS
│   └── port_XXXX/       # Autres ports web
├── smb/
│   ├── nxc_hosts.txt    # Hosts générés par NetExec
│   ├── smbmap_auth.txt  # SMB authentifié
│   └── enum4linux.txt   # Énumération
└── NOTION_EXPORT.json   # Ce fichier
    """
    
    notion_data["children"].append({
        "object": "block",
        "type": "code",
        "code": {
            "language": "plain text",
            "rich_text": [{"text": {"content": file_structure.strip()}}]
        }
    })
    
    # ⚠️ Disclaimer
    notion_data["children"].append({
        "object": "block",
        "type": "callout",
        "callout": {
            "icon": {"emoji": "⚠️"},
            "color": "red_background",
            "rich_text": [{"text": {"content": "CADRE LÉGAL : Exploitation uniquement sous ROE/NDA valide"}}]
        }
    })
    
    # Footer
    notion_data["children"].append({
        "object": "block",
        "type": "divider",
        "divider": {}
    })
    
    notion_data["children"].append({
        "object": "block",
        "type": "paragraph",
        "paragraph": {
            "rich_text": [{"text": {"content": f"🦊 RESCI ENUM v11.0 — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}}]
        }
    })
    
    # Sauvegarder le JSON
    notion_file = base / "exports" / "NOTION_EXPORT.json"
    notion_file.parent.mkdir(parents=True, exist_ok=True)
    
    with notion_file.open("w", encoding="utf-8") as f:
        json.dump(notion_data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"[📊] Export Notion généré: {notion_file}")
    
    # Générer aussi le script d'upload
    upload_script = base / "exports" / "upload_to_notion.sh"
    script_content = f"""#!/bin/bash
# Script d'upload vers Notion
# Prérequis: pip install notion-client

# Configuration
NOTION_TOKEN="your_notion_integration_token_here"
DATABASE_ID="your_database_id_here"

# Upload
python3 << 'EOF'
from notion_client import Client
import json

notion = Client(auth="$NOTION_TOKEN")

with open("{notion_file}", "r") as f:
    data = json.load(f)

# Créer la page dans la database
response = notion.pages.create(
    parent={{"database_id": "$DATABASE_ID"}},
    properties=data["properties"],
    children=data["children"]
)

print(f"✅ Page créée: {{response['url']}}")
EOF
"""
    
    upload_script.write_text(script_content)
    upload_script.chmod(0o755)
    
    logger.info(f"[📤] Script d'upload: {upload_script}")
    logger.info("[ℹ️] Configurer NOTION_TOKEN et DATABASE_ID dans upload_to_notion.sh")
    
    return notion_file

def generate_findings(ports: List[int], http_services: Dict[int, str]) -> Dict:
    """Analyse et génère les findings."""
    findings = {"vectors": []}
    
    if http_services:
        findings["vectors"].append({
            "emoji": "🌐",
            "title": f"Surface Web ({len(http_services)} service(s))",
            "description": f"Services HTTP détectés sur ports: {', '.join(map(str, sorted(http_services.keys())))}"
        })
    
    if 445 in ports or 139 in ports:
        findings["vectors"].append({
            "emoji": "🧠",
            "title": "SMB / Active Directory",
            "description": "- Énumération utilisateurs/groupes\n- Partages accessibles"
        })
    
    return findings

# ============================================================
# 🚀 MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="🦊 RESCI ENUM Framework v11.0 - Auto Adaptive Full Scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  # Scan complet automatique (RECOMMANDÉ)
  %(prog)s 10.10.10.100

  # 🔥 Mode VPN-safe pour HackTheBox/TryHackMe (RECOMMANDÉ pour VPN)
  %(prog)s 10.10.10.100 --vpn-mode

  # Scan avec authentification SMB/Web
  %(prog)s 10.10.10.100 -u john.w -p 'RFulUtONCOL!' -d darkzero.htb --vpn-mode

  # Scan rapide (wordlist réduite)
  %(prog)s 10.10.10.100 --mode fast --vpn-mode
        """
    )
    
    parser.add_argument("target", help="Cible (IP ou hostname)")
    parser.add_argument("--mode", choices=["fast", "full"], default="full",
                        help="Mode de scan (défaut: full)")
    parser.add_argument("--domain", "-d", type=str, default=None,
                        help="Domaine pour énumération DNS/AD")
    
    # 🆕 AUTHENTIFICATION
    auth_group = parser.add_argument_group('🔐 Authentification')
    auth_group.add_argument("--username", "-u", type=str, default=None,
                           help="Nom d'utilisateur pour SMB/Web")
    auth_group.add_argument("--password", "-p", type=str, default=None,
                           help="Mot de passe pour SMB/Web")
    
    # Modules
    modules_group = parser.add_argument_group('📦 Modules optionnels')
    modules_group.add_argument("--ad-full", action="store_true",
                              help="Énumération AD complète")
    modules_group.add_argument("--web-aggressive", action="store_true",
                              help="Fuzzing web agressif avec Nuclei")
    modules_group.add_argument("--loot-mode", action="store_true",
                              help="Recherche automatique de credentials")
    
    # Options
    options_group = parser.add_argument_group('⚙️ Options')
    options_group.add_argument("--vpn-mode", action="store_true",
                              help="🔥 Mode VPN-safe : réduit threads/delay pour éviter saturation (RECOMMANDÉ pour HTB/VPN)")
    options_group.add_argument("--auto-hosts", action="store_true",
                              help="Ajoute automatiquement les domaines découverts dans /etc/hosts (nécessite sudo)")
    options_group.add_argument("--debug", action="store_true",
                              help="Active les logs de débogage détaillés")
    options_group.add_argument("--no-udp", action="store_true",
                              help="Désactiver le scan UDP")
    options_group.add_argument("--no-dns", action="store_true",
                              help="Désactiver l'énumération DNS")
    options_group.add_argument("--report-level", choices=["summary", "full"], default="full",
                              help="Niveau de détail du rapport Markdown (défaut: full)")
    
    args = parser.parse_args()
    
    # Validation authentification
    if (args.username and not args.password) or (args.password and not args.username):
        parser.error("--username et --password doivent être utilisés ensemble")

    # Validation de la cible
    if not validate_target(args.target):
        parser.error(f"Cible invalide: '{args.target}' n'est pas une IP ou hostname valide")

    flags = []
    start_time = datetime.now()
    base = Path(f"resci_enum_{args.target}_{start_time.strftime('%Y%m%d_%H%M%S')}")
    
    print(BANNER)
    setup_dirs(base)
    logger = setup_logging(base, debug=args.debug)
    
    logger.info(f"[🦊] Démarrage sur {args.target}")
    logger.info(f"[📁] Répertoire: {base}")

    if args.vpn_mode:
        logger.info("[🔥] MODE VPN ACTIVÉ - Scans optimisés pour éviter saturation")
        logger.info("[🔥] Gobuster: 10 threads, 200ms delay | Récursif: 8 threads, 250ms delay")
    else:
        logger.info("[ℹ️] Mode normal - Pour HTB/VPN, utilisez --vpn-mode")

    if args.username:
        logger.info(f"[🔐] Authentification: {args.username}")
        if args.domain:
            logger.info(f"[🏢] Domaine: {args.domain}")
    
    # Phase 0: Reconnaissance
    logger.info("[0/6] 🔍 Reconnaissance de base...")
    basic_recon(args.target, base)
    
    # Phase 1: Discovery
    logger.info("[1/6] 🔎 Scan des ports...")
    ports = rustscan(args.target, base)

    if not ports:
        logger.error("[❌] Aucun port détecté")
        sys.exit(1)

    # 🆕 Forcer l'inclusion des ports web communs pour éviter de les manquer
    common_web_ports = {80, 443, 8080, 8443}
    ports_set = set(ports)
    new_web_ports = common_web_ports - ports_set
    if new_web_ports:
        ports = sorted(ports_set | common_web_ports)
        logger.info(f"[🌐] Ajout de {len(new_web_ports)} port(s) web commun(s) au scan: {sorted(new_web_ports)}")

    logger.info("[2/6] 🔍 Scan TCP détaillé...")
    nmap_tcp(args.target, ports, base)
    
    if not args.no_udp:
        logger.info("[3/6] 📡 Scan UDP...")
        nmap_udp(args.target, base, args.mode)
    else:
        logger.info("[3/6] ⏭️ Scan UDP ignoré")
    
    # Détection HTTP
    logger.info("[🌐] Détection des services HTTP...")
    http_services = detect_http_services(base)
    
    # Phase 2: Énumération
    logger.info("[4/6] 🎯 Énumération des services...")
    
    if (53 in ports or args.domain) and not args.no_dns:
        logger.info("[🌐] Énumération DNS...")
        enum_dns(args.target, base, args.domain)
    
    tasks = []
    
    # Web
    if http_services:
        tasks.append(("Web", lambda: enum_web(
            args.target, http_services, base, args.mode,
            args.username, args.password, args.vpn_mode, args.auto_hosts
        )))
    
    # SMB
    if 445 in ports or 139 in ports:
        tasks.append(("SMB", lambda: enum_smb(
            args.target, base, 
            args.username, args.password, args.domain
        )))
    
    if 21 in ports:
        tasks.append(("FTP", lambda: enum_ftp(args.target, base)))
    if 161 in ports:
        tasks.append(("SNMP", lambda: enum_snmp(args.target, base)))
    if any(p in NFS_PORTS for p in ports):
        tasks.append(("NFS", lambda: enum_nfs(args.target, base)))
    if 88 in ports:
        tasks.append(("Kerberos", lambda: enum_kerberos(args.target, base)))
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(task[1]): task[0] for task in tasks}
        for future in as_completed(futures):
            service = futures[future]
            try:
                future.result()
                logger.info(f"[✅] {service} terminé")
            except Exception as e:
                logger.error(f"[❌] {service} échoué: {e}")
    
    # Phase 3: Modules optionnels
    logger.info("[5/6] 🔧 Modules optionnels...")

    # 🆕 AD Full auto-activé si Kerberos détecté (port 88)
    if args.ad_full or (88 in ports and args.username):
        if 88 in ports and args.username and not args.ad_full:
            logger.info("[🎯] AD Full auto-activé (Kerberos détecté + credentials fournis)")
        flags.append("ad-full")
        enum_ad_full(args.target, base, args.username, args.password)

    if args.web_aggressive:
        flags.append("web-aggressive")
        enum_web_aggressive(base)

    # 🆕 Loot mode activé par défaut si des services web ont été trouvés
    if args.loot_mode or http_services:
        if http_services and not args.loot_mode:
            logger.info("[🎯] Loot mode auto-activé (services web détectés)")
        flags.append("loot-mode")
        loot_mode(base)
    
    enum_searchsploit(base)
    
    # Phase 4: Rapport
    logger.info("[6/6] 📊 Génération des rapports...")
    
    end_time = datetime.now()
    duration = end_time - start_time
    duration_str = f"{int(duration.total_seconds() // 60)}m {int(duration.total_seconds() % 60)}s"
    
    findings = generate_findings(ports, http_services)
    findings["duration"] = duration_str

    # 🆕 Export Markdown Report
    markdown_report = export_markdown_report(
        args.target, ports, http_services, base, args.mode, findings,
        args.report_level, args.username, args.domain
    )

    # Export Notion (JSON)
    notion_file = export_notion_json(
        args.target, ports, http_services, base, args.mode, findings,
        args.username, args.domain
    )
    
    # Résumé final
    print("\n" + "="*70)
    print("🦊 ÉNUMÉRATION TERMINÉE")
    print("="*70)
    print(f"⏱️  Durée          : {duration_str}")
    print(f"📁 Répertoire     : {base}")
    print(f"🔎 Ports trouvés  : {len(ports)}")
    print(f"🌐 Services web   : {len(http_services)}")
    if http_services:
        print(f"   Ports web      : {', '.join(map(str, sorted(http_services.keys())))}")
    if args.username:
        print(f"🔐 Authentification: {args.username}@{args.domain or args.target}")

    # 🆕 Affichage des fichiers sensibles trouvés
    loot_dir = base / "loot"
    if loot_dir.exists():
        sensitive_files = list(loot_dir.glob("*"))
        if sensitive_files:
            print(f"🔴 Fichiers sensibles: {len(sensitive_files)}")
            for f in sensitive_files[:5]:  # Max 5 fichiers
                print(f"   └─ {f.name}")
            if len(sensitive_files) > 5:
                print(f"   └─ ... et {len(sensitive_files) - 5} autres")

    print(f"🎯 Vecteurs       : {len(findings['vectors'])}")
    print(f"📄 Rapport MD     : {markdown_report}")
    print(f"📊 Export Notion  : {notion_file}")
    print("="*70)
    
    # Rappel hosts file
    hosts_file = base / "smb" / "nxc_hosts.txt"
    if hosts_file.exists():
        print("\n⚠️  N'oubliez pas de mettre à jour /etc/hosts:")
        print(f"   sudo cat {hosts_file} >> /etc/hosts\n")

    # 🆕 Suggestions de commandes rapides
    print("\n💡 COMMANDES RAPIDES:")
    print(f"   📄 Voir le rapport complet: cat {markdown_report}")
    if http_services:
        for port in sorted(http_services.keys())[:2]:  # Max 2 services web
            tree_file = base / "web" / f"port_{port}" / "directory_tree.txt"
            if tree_file.exists():
                print(f"   🌳 Arborescence web:{port}: cat {tree_file}")
    if loot_dir.exists() and list(loot_dir.glob("*")):
        print(f"   🔴 Fichiers sensibles: ls -lah {loot_dir}/")

    print("\n⚠️  Exploitation uniquement sous ROE/NDA valide")
    print("🦊 Bon pentest !")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[⚠️] Interruption utilisateur")
        sys.exit(1)
    except Exception as e:
        logging.error(f"[❌] Erreur fatale: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)