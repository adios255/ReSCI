# 🦊 ReSCI Framework

Framework d'énumération **complet et auto-adaptatif** pour le pentest et les labs offensifs.

Il enchaîne automatiquement les phases de recon → scan → énumération de services → modules optionnels → rapport, en adaptant les scans aux services détectés.

## ✨ Fonctionnalités

- **Discovery** : rustscan + nmap (TCP détaillé, UDP), ajout auto des ports web courants
- **Web** : détection dynamique des services HTTP/HTTPS, énumération de répertoires (gobuster/ffuf), vhosts, fingerprinting de techno
- **Services** : SMB, FTP, LDAP, SNMP, NFS, Kerberos
- **Active Directory** : mode AD Full auto-activé si Kerberos + credentials
- **Loot mode** : collecte de fichiers sensibles, détection de secrets (regex)
- **searchsploit** : corrélation automatique des versions détectées
- **Rapports** : export Markdown (`summary`/`full`) + export JSON pour Notion
- **Mode VPN** : scans throttlés pour HTB/VPN (évite la saturation)
- Gestion `/etc/hosts`, logging complet, validation de la cible

## 🚀 Usage

```bash
# Cible simple (mode full par défaut)
python3 ReSCI_Framework_V11.py 10.10.10.10

# Avec credentials + domaine (AD)
python3 ReSCI_Framework_V11.py dc01.exemple.htb --username user --password 'pass' --domain exemple.htb

# Mode VPN (HTB) + rapport résumé
python3 ReSCI_Framework_V11.py 10.10.10.10 --vpn-mode --report-level summary
```

Aide complète :

```bash
python3 ReSCI_Framework_V11.py --help
```

## 🧰 Prérequis

`nmap`, `rustscan`, `gobuster` et/ou `ffuf`, `smbclient` / `netexec` (nxc), `snmpwalk`, `showmount`, `searchsploit`, wordlists `dirb` / `dirbuster` / `seclists`.
Environnement recommandé : **Kali** ou **Parrot**.

> ⚠️ Usage strictement légal — voir l'[avertissement du projet](../README.md#️-avertissement-légal).
