# ⚙ Le Bouclier Cyborg — Pare-feu Pédagogique

> *"Mon corps est une machine. Mon réseau aussi."*

Projet de cybersécurité inspiré de **Cyborg** (Teen Titans) — un outil CLI pour apprendre,
configurer et simuler un pare-feu réseau, avec l'esthétique mi-humain, mi-machine du personnage.

---

## Formation ciblée

| Programme | Compétences couvertes |
|---|---|
| **Bachelor CSR** | Administration réseau, filtrage de trafic, politique de sécurité |
| **M1/M2 Cybersécurité & Cloud** | Architecture défensive, analyse comportementale, Zero-Trust préparatoire |

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
└── default_rules.json        # Règles de base prêtes à l'emploi
tests/
├── test_rules.py             # Tests moteur, CIDR, persistence, CRUD
└── test_traffic.py           # Tests simulateur de trafic
```

---

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

---

## Utilisation

### Afficher les règles actives

```bash
cyborg-shield rules list
```

### Ajouter une règle (ex : bloquer le port 23 Telnet)

```bash
cyborg-shield rules add --chain INPUT --protocol tcp --port 23 --action DROP --comment "Bloquer Telnet"
```

### Charger un profil prédéfini

```bash
# Profils disponibles : ssh-protect | web-server | dmz | strict
cyborg-shield preset web-server
```

### Simuler du trafic réseau

```bash
# 50 paquets, 30% de trafic malveillant, avec log CSV
cyborg-shield simulate --packets 50 --attack-ratio 0.3 --log-csv
```

### Tester un paquet contre les règles

```bash
cyborg-shield test-packet --src 192.168.99.1 --port 22 --protocol tcp
```

### Gérer les règles

```bash
cyborg-shield rules toggle 3      # Activer/désactiver la règle #3
cyborg-shield rules remove 3      # Supprimer la règle #3
cyborg-shield rules flush --chain INPUT --confirm
```

### Interface avec iptables (root requis)

```bash
sudo cyborg-shield rules add --port 4444 --action DROP --apply-iptables
cyborg-shield rules iptables --chain INPUT
```

---

## Profils de sécurité

| Profil | Usage | Règles |
|---|---|---|
| `ssh-protect` | Serveur avec accès SSH seul | Autorise SSH, bloque Telnet/RDP |
| `web-server` | Serveur HTTP/HTTPS | HTTP + HTTPS + SSH, DROP par défaut |
| `dmz` | Zone démilitarisée | Isolation stricte des flux FORWARD |
| `strict` | Durcissement maximal | SSH uniquement, tout le reste DROP |

---

## Tests

```bash
pytest tests/ -v
```

---

## Concepts couverts

- **Chaînes** : INPUT / OUTPUT / FORWARD (modèle Netfilter / iptables)
- **First-match wins** : ordre des règles et priorité
- **CIDR matching** : filtrage par sous-réseau (`192.168.0.0/24`)
- **Actions** : ALLOW / BLOCK (REJECT) / DROP / LOG
- **Politique par défaut** : comportement sans règle correspondante
- **Persistance** : sauvegarde JSON, chargement au démarrage
- **Audit** : chaque modification est journalisée dans `logs/audit_*.log`
- **Simulation** : génération de trafic avec signatures d'attaque réelles (SSH brute-force, RDP scan, SMB exploit, Tor exit node)

---

## Structure des logs

```
logs/
├── traffic_YYYY-MM-DD.csv     # Chaque paquet simulé
├── traffic_YYYY-MM-DD.jsonl   # Format JSON Lines
└── audit_YYYY-MM-DD.log       # Modifications des règles
```

---

*Teen Titans — Cyborg : "BOOYAH!" ⚡*
