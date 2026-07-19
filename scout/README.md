# 🦊 ReSCI Scout

Énumération réseau **rapide, discrète et ciblée** — le « LinPEAS de l'énumération réseau ».

Là où le Framework vise l'exhaustivité, le Scout privilégie la vitesse et le contrôle du bruit, et fait remonter les **Quick Wins** en premier.

## ✨ Fonctionnalités

- **Profils de bruit** : `stealth` / `fast` / `deep` / `network` — tu choisis le compromis discrétion ↔ exhaustivité
- **Cibles souples** : IP, hostname, nom NetBIOS, **CIDR** (réseau) ou liste (`-iL`)
- **Panneau Quick Wins** : les gains rapides sont affichés en tête
- Sortie colorée (désactivable via `--no-color`), UTF-8 forcé (compatible Windows)
- Logging et organisation des résultats

## 🚀 Usage

```bash
# Énumération rapide d'une cible
python3 ReSCI_Scout_V12.py 10.10.10.10

# Profil discret
python3 ReSCI_Scout_V12.py 10.10.10.10 --profile stealth

# Balayage d'un réseau
python3 ReSCI_Scout_V12.py 10.10.10.0/24 --profile network
```

Aide complète :

```bash
python3 ReSCI_Scout_V12.py --help
```

## 🧰 Prérequis

`nmap`, et selon les modules activés : `netexec` (nxc), `smbclient`, outils web. Environnement recommandé : **Kali** / **Parrot**.

> ⚠️ Usage strictement légal — voir l'[avertissement du projet](../README.md#️-avertissement-légal).
