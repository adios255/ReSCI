# 🦊 ReSCI — Recon · Enum · Scout · IA

> Boîte à outils d'énumération et de reconnaissance réseau pour le pentest et les labs offensifs (HTB / THM).

ReSCI regroupe deux outils complémentaires écrits en Python. L'un vise l'**exhaustivité** (le gros framework tout-en-un), l'autre la **rapidité et la discrétion** (le scout léger). Les deux produisent des sorties organisées et des rapports exploitables.

---

## ⚠️ Avertissement légal

Ces outils sont destinés **exclusivement** à un usage légal :
- environnements de lab (Hack The Box, TryHackMe…),
- systèmes dont vous êtes propriétaire,
- engagements couverts par un **ROE / mandat / NDA** valide et signé.

Toute utilisation contre un système sans autorisation écrite est **illégale**. L'auteur décline toute responsabilité en cas d'usage abusif.

---

## 📦 Les outils

| Outil | Dossier | Résumé |
|-------|---------|--------|
| **ReSCI Framework** | [`framework/`](framework/) | Énumération complète et adaptative : nmap/rustscan, web (gobuster/ffuf), SMB, LDAP, SNMP, NFS, Kerberos/AD, searchsploit, rapports Markdown + export Notion. |
| **ReSCI Scout** | [`scout/`](scout/) | Énumération rapide, discrète et ciblée (« LinPEAS de l'énum réseau ») : profils de bruit stealth/fast/deep/network, panneau *Quick Wins*, support CIDR et listes de cibles. |

Voir le `README.md` de chaque dossier pour l'installation et l'usage détaillés.

---

## 🚀 Démarrage rapide

```bash
git clone https://github.com/adios255/ReSCI.git
cd ReSCI

# Scout (rapide)
python3 scout/ReSCI_Scout_V12.py <cible>

# Framework (complet)
python3 framework/ReSCI_Framework_V11.py <cible>
```

> Prérequis (selon les modules) : `nmap`, `rustscan`, `gobuster`/`ffuf`, `nmap`, `smbclient`/`netexec`, `seclists`, `searchsploit`… installés et dans le `PATH`. Testé sous Kali / Parrot.

---

## 🗂️ Versioning

Chaque outil est versionné **individuellement** dans son propre `CHANGELOG.md`.
Les versions publiées correspondent aux **tags git** (`framework-v11`, `scout-v12`, …) et aux *Releases* GitHub.

---

## 📄 Licence

Distribué sous licence [MIT](LICENSE).

## ✍️ Auteur

**J.ADIOS**
