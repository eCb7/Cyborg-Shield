# ⚙ Le Bouclier Cyborg — Pare-feu Pédagogique

> *"Mon corps est une machine. Mon réseau aussi."*

---

## C'est quoi ?

**Le Bouclier Cyborg** est une **application en ligne de commande (CLI)** Python qui simule
un pare-feu réseau. Elle permet de créer des règles de filtrage, de les tester sur du trafic
simulé, et de comprendre les mécanismes de défense réseau — sans avoir besoin d'être root.

Elle s'interface aussi avec **iptables** sur Linux si tu veux appliquer tes règles dans le
vrai système (root requis dans ce cas uniquement).

| Programme | Compétences couvertes |
|---|---|
| **Bachelor CSR** | Administration réseau, filtrage de trafic, politique de sécurité |
| **M1/M2 Cybersécurité & Cloud** | Architecture défensive, analyse comportementale, Zero-Trust préparatoire |

---

## Prérequis

- Python **3.10 ou supérieur**
- Un terminal (Linux, macOS, WSL sur Windows)
- Pas besoin d'être root pour utiliser le mode simulation

Vérifier ta version Python :
```bash
python3 --version
```

---

## Installation

**Étape 1 — Cloner le dépôt** (si pas déjà fait)
```bash
git clone <url-du-repo>
cd Cyborg-Shield
```

**Étape 2 — Installer les dépendances**
```bash
pip install -r requirements.txt
```

C'est tout. Deux dépendances uniquement : `click` (CLI) et `rich` (interface terminal colorée).

---

## Démarrage rapide

L'application se lance avec `python -m cyborg_shield.main` suivi d'une commande.

```bash
# 1. Charger un profil de sécurité prêt à l'emploi
python -m cyborg_shield.main preset web-server

# 2. Simuler du trafic réseau (20 paquets, 30% d'attaques)
python -m cyborg_shield.main simulate -n 20 -r 0.3

# 3. Voir les règles actives
python -m cyborg_shield.main rules list
```

> **Raccourci optionnel** : si tu veux taper `cyborg-shield` au lieu de `python -m cyborg_shield.main`,
> lance une fois : `make install` ou `pip install -e .` (nécessite setuptools récent).

---

## Toutes les commandes

### `rules list` — Voir les règles

```bash
python -m cyborg_shield.main rules list
```

Affiche un tableau avec toutes les règles actives : chaîne, protocole, IP source/destination,
port, action, et nombre de paquets filtrés (hits).

---

### `rules add` — Ajouter une règle

```bash
python -m cyborg_shield.main rules add [OPTIONS]
```

| Option | Court | Valeurs possibles | Défaut | Description |
|---|---|---|---|---|
| `--chain` | `-c` | `INPUT` `OUTPUT` `FORWARD` | `INPUT` | Chaîne de filtrage |
| `--protocol` | `-p` | `tcp` `udp` `icmp` `any` | `any` | Protocole |
| `--src` | `-s` | IP ou CIDR (`192.168.0.0/24`) | `any` | IP source |
| `--dst` | `-d` | IP ou CIDR | `any` | IP destination |
| `--port` | `-P` | Nombre entier | aucun | Port destination |
| `--action` | `-a` | `ALLOW` `BLOCK` `DROP` `LOG` | `BLOCK` | Action à appliquer |
| `--comment` | `-m` | Texte libre | `""` | Description de la règle |
| `--apply-iptables` | — | flag | non | Applique aussi dans iptables système (root) |

**Exemples :**
```bash
# Bloquer Telnet (port 23)
python -m cyborg_shield.main rules add -p tcp -P 23 -a DROP -m "Telnet interdit"

# Bloquer toute une plage IP en entrée
python -m cyborg_shield.main rules add -s 185.220.0.0/16 -a BLOCK -m "Plage Tor"

# Autoriser HTTPS depuis n'importe où
python -m cyborg_shield.main rules add -p tcp -P 443 -a ALLOW -m "HTTPS ok"

# Bloquer le RDP et l'appliquer dans iptables (root)
sudo python -m cyborg_shield.main rules add -p tcp -P 3389 -a DROP --apply-iptables
```

---

### `rules remove` / `toggle` / `flush` — Gérer les règles

```bash
# Supprimer la règle #3
python -m cyborg_shield.main rules remove 3

# Activer ou désactiver temporairement la règle #2 (sans la supprimer)
python -m cyborg_shield.main rules toggle 2

# Vider toutes les règles de la chaîne INPUT
python -m cyborg_shield.main rules flush --chain INPUT --confirm

# Vider TOUTES les règles
python -m cyborg_shield.main rules flush --confirm
```

---

### `preset` — Profils prédéfinis

Charge un ensemble de règles cohérent en une seule commande.

```bash
python -m cyborg_shield.main preset <nom-du-profil>
```

| Profil | Cas d'usage | Ce qu'il fait |
|---|---|---|
| `ssh-protect` | Serveur SSH uniquement | Autorise le port 22, bloque Telnet (23) et RDP (3389) |
| `web-server` | Serveur web | Autorise HTTP (80), HTTPS (443) et SSH (22), bloque tout le reste |
| `dmz` | Zone démilitarisée | Filtre le trafic FORWARD entre réseau interne et DMZ |
| `strict` | Durcissement maximal | SSH seulement en entrée, tout le reste DROP |

```bash
# Exemple : configurer un serveur web
python -m cyborg_shield.main preset web-server
```

> Les profils s'ajoutent aux règles existantes. Pour repartir de zéro : `rules flush --confirm` d'abord.

---

### `simulate` — Simuler du trafic

Lance une simulation de trafic réseau (légitime + attaques) et applique tes règles en temps réel.

```bash
python -m cyborg_shield.main simulate [OPTIONS]
```

| Option | Court | Défaut | Description |
|---|---|---|---|
| `--packets` | `-n` | `20` | Nombre de paquets à générer |
| `--attack-ratio` | `-r` | `0.3` | Part de trafic malveillant (0.0 à 1.0) |
| `--rate` | — | `5.0` | Paquets par seconde |
| `--log-csv` | — | non | Sauvegarde les événements dans `logs/traffic_DATE.csv` |
| `--log-json` | — | non | Sauvegarde en `logs/traffic_DATE.jsonl` |

```bash
# Simulation rapide : 50 paquets, 40% d'attaques, log CSV
python -m cyborg_shield.main simulate -n 50 -r 0.4 --log-csv

# Simulation lente et détaillée (1 paquet/sec)
python -m cyborg_shield.main simulate -n 30 --rate 1
```

**Signatures d'attaque simulées :** SSH brute-force, RDP scan, SMB exploit, Tor exit node, Telnet probe.

Si aucune règle n'est configurée, les règles par défaut sont chargées automatiquement.

---

### `test-packet` — Tester un paquet

Vérifie quelle décision le pare-feu prendrait face à un paquet précis — sans modifier quoi que ce soit.

```bash
python -m cyborg_shield.main test-packet [OPTIONS]
```

| Option | Court | Requis | Description |
|---|---|---|---|
| `--src` | `-s` | oui | IP source du paquet |
| `--dst` | `-d` | non | IP destination (défaut : `10.0.0.1`) |
| `--protocol` | `-p` | non | `tcp` / `udp` / `icmp` (défaut : `tcp`) |
| `--port` | `-P` | non | Port destination |
| `--chain` | `-c` | non | Chaîne à évaluer (défaut : `INPUT`) |

```bash
# Est-ce qu'une connexion SSH depuis 192.168.99.1 passerait ?
python -m cyborg_shield.main test-packet -s 192.168.99.1 -P 22 -p tcp

# Est-ce qu'une connexion RDP externe serait bloquée ?
python -m cyborg_shield.main test-packet -s 91.108.4.1 -P 3389 -p tcp
```

---

### `rules iptables` — Inspecter iptables système

```bash
# Voir toutes les règles iptables actives sur la machine
python -m cyborg_shield.main rules iptables

# Voir uniquement la chaîne INPUT
python -m cyborg_shield.main rules iptables --chain INPUT
```

> Affiche les règles du vrai système même si elles n'ont pas été créées via cette appli.

---

## Raccourcis Make

```bash
make install   # Installer les dépendances
make test      # Lancer les 19 tests unitaires
make demo      # Démo complète : preset + simulation + test-packet
make reset     # Effacer les règles sauvegardées (repart de zéro)
make help      # Afficher l'aide CLI
```

---

## Tests unitaires

```bash
python -m pytest tests/ -v
```

19 tests couvrent : moteur first-match, matching CIDR, CRUD des règles, persistance JSON,
activation/désactivation, simulateur de trafic.

---

## Architecture

```
cyborg_shield/
├── firewall/
│   ├── rules.py              # Moteur de règles (first-match, CIDR, protocoles)
│   └── iptables_adapter.py   # Pont vers iptables système (root optionnel)
├── monitor/
│   └── traffic.py            # Simulateur de trafic + signatures d'attaque
├── ui/
│   ├── ascii_art.py          # ASCII art Cyborg
│   ├── theme.py              # Palette bleu/argent (Rich)
│   └── dashboard.py          # HUD terminal — tables, stats, BOOYAH!
└── utils/
    └── logger.py             # Journal CSV / JSONL / audit

config/
├── default_rules.json        # Règles de référence (non modifiées)
└── rules.json                # Règles actives — créé automatiquement

logs/
├── traffic_YYYY-MM-DD.csv    # Généré par --log-csv
├── traffic_YYYY-MM-DD.jsonl  # Généré par --log-json
└── audit_YYYY-MM-DD.log      # Toutes les modifications de règles
```

---

## Concepts réseau couverts

| Concept | Où ça apparaît |
|---|---|
| **Chaînes INPUT / OUTPUT / FORWARD** | Options `--chain` de toutes les commandes |
| **First-match wins** | Ordre des règles — la première qui correspond gagne |
| **CIDR** | `--src 192.168.0.0/24` filtre un sous-réseau entier |
| **ALLOW / BLOCK / DROP** | BLOCK envoie un rejet explicite, DROP ne répond pas |
| **Politique par défaut** | Sans règle correspondante : ALLOW (configurable) |
| **Audit trail** | Chaque `add` / `remove` / `flush` est logué dans `logs/audit_*.log` |
| **Simulation d'intrusion** | SSH brute-force, RDP scan, SMB exploit, Tor, Telnet probe |

---

## Dépannage

**`python -m cyborg_shield.main` ne fonctionne pas**
→ Vérifie que tu es dans le dossier `Cyborg-Shield/` et que Python 3.10+ est utilisé.

**`ModuleNotFoundError: No module named 'click'`**
→ Lance `pip install -r requirements.txt`

**`iptables: command not found`**
→ Normal sur macOS ou sans root — le mode simulation fonctionne sans iptables.

**Les règles ont disparu**
→ Elles sont dans `config/rules.json`. Si le fichier n'existe pas, utilise `preset` ou `rules add`.

---

*Teen Titans — Cyborg : "BOOYAH!" ⚡*
