# URLINT

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![HTTP](https://img.shields.io/badge/http-httpx-green)
![CLI](https://img.shields.io/badge/interface-CLI-lightgrey)
![Use](https://img.shields.io/badge/use-defensive%20OSINT-orange)

`URLINT` est un outil CLI Python pour faire de la reconnaissance OSINT légère, légale et défensive sur des noms de domaine générés à partir de mots-clés.

Il génère des variantes de domaines, teste leur existence technique, récupère les signaux utiles et classe les résultats sans scanner de chemins, sans brute-force massif et sans contourner les protections anti-bot.

```bash
URLINT baguette tradition
```

Exemple de sortie :

```text
1 RESULT FOUND: baguette-tradition.fr

Domain                | Type     | Proto | Code | Server | Title
----------------------+----------+-------+------+--------+-------------------
baguette-tradition.fr | web_site | https | 200  | nginx  | Baguette Tradition
```

## Fonctionnalités

- Génération de domaines depuis des mots-clés : `baguettetradition.fr`, `baguette-tradition.fr`, etc.
- Sous-combinaisons ordonnées : `baguette tradition artisanale` génère aussi `baguettetradition`.
- Priorité aux candidats utilisant tous les mots utiles avant les sous-combinaisons.
- Stopwords français ignorés par défaut : `et`, `de`, `la`, `le`, `les`, etc.
- Exclusion des mots isolés avec `--no-single-words` ou `--exclude-words`.
- TLDs manuels, groupes TLD intégrés, fichier local ou liste IANA officielle.
- Résolution DNS avec récupération d'IP.
- Ping optionnel compatible Linux/macOS/Windows.
- Probes HTTPS puis HTTP via `httpx`.
- `HEAD` d'abord, puis `GET` limité à 64 KiB uniquement pour extraire le `<title>`.
- Détection basique des redirects et du serveur HTTP.
- Tableau final lisible en console, affiché une fois le scan terminé.
- Barre de progression automatique avec temps écoulé pendant le scan.
- Domaines ou URLs cliquables dans les terminaux compatibles.
- Export JSON et CSV.

## Installation

```bash
git clone https://github.com/MagikarpLv13/URLINT.git
cd URLINT
python -m venv .venv
```

Activer l'environnement virtuel :

```bash
# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

# Windows cmd.exe
.venv\Scripts\activate.bat
```

Installer URLINT :

```bash
python -m pip install .
```

Sans installation :

```bash
python -m urlint baguette tradition --no-ping --max-results 4
```

La commande principale installée est `URLINT`. La commande lowercase `urlint` reste disponible comme alias. Le module Python reste `urlint`, donc `python -m urlint` reste la bonne forme sans installation.

## Quick Start

Tester quelques TLDs :

```bash
URLINT baguette artisanale --tlds fr,com,org --timeout 3 --no-ping
```

Voir les domaines générés sans requêtes réseau :

```bash
URLINT la meilleure baguette artisanale --tlds fr,com,eu --dry-run --keep-stopwords
```

Utiliser des groupes TLD prêts à l'emploi :

```bash
URLINT baguette tradition --tld-groups france_francophone,global_common --max-results 50
```

Scanner prudemment avec la liste IANA :

```bash
URLINT baguette artisanale --iana-tlds --dry-run
URLINT baguette artisanale --iana-tlds --max-results 1500 --delay 1 --timeout 2 --no-ping
```

## Génération Des Candidats

Commande :

```bash
URLINT la meilleure baguette artisanale --tlds fr,com,eu --dry-run --keep-stopwords
```

Sortie partielle :

```text
lameilleurebaguetteartisanale.fr
lameilleurebaguetteartisanale.com
lameilleurebaguetteartisanale.eu
la-meilleure-baguette-artisanale.fr
la-meilleure-baguette-artisanale.com
la-meilleure-baguette-artisanale.eu
meilleurebaguetteartisanale.fr
meilleure-baguette-artisanale.fr
baguetteartisanale.fr
baguette-artisanale.fr
```

Par défaut, `URLINT` ignore les mots de liaison courants. Ajoutez `--keep-stopwords` si vous voulez les conserver.

Pour éviter les domaines trop génériques issus d'un seul mot :

```bash
URLINT la meilleure baguette artisanale --no-single-words
```

Pour exclure seulement certains mots isolés tout en gardant les autres :

```bash
URLINT la meilleure baguette artisanale --exclude-words meilleure,artisanale
```

Cela peut garder `baguette.fr`, mais éviter `meilleure.fr` et `artisanale.fr`.

## Groupes TLD Intégrés

Lister les groupes disponibles :

```bash
URLINT --list-tld-groups
```

Exemples de groupes :

| Groupe | Usage |
| --- | --- |
| `global_common` | TLDs globaux fréquents |
| `france_francophone` | France, territoires et espace francophone |
| `europe` | Pays et TLDs géographiques européens |
| `tech_dev_it` | Tech, dev, cloud, software, sécurité |
| `business_company` | Entreprises, holdings, services, consulting |
| `commerce_retail` | Shop, store, retail, vente |
| `security_triage_high_signal` | Triage défensif et signaux courants |
| `lookalike_brand_risk_common` | Risque marque, phishing et lookalike |

Les TLDs provenant de plusieurs sources sont unifiés et dédupliqués en conservant l'ordre. Par exemple :

```bash
URLINT baguette tradition --tld-groups france_francophone,global_common --tlds fr,com
```

Si `fr` ou `com` apparaissent déjà dans un groupe, ils ne seront testés qu'une seule fois.

Ordre de priorité des sources :

1. `--tlds-file`
2. `--tld-groups`
3. `--tlds`
4. TLDs par défaut si aucune source n'est fournie

`--iana-tlds` est un mode séparé : il charge tous les TLDs actuellement autorisés dans la racine IANA et ne se combine pas avec `--tld-groups`. C'est le mode le plus complet, mais aussi le plus gourmand en volume de candidats.

## Options Principales

```text
--json                  sortie JSON
--csv fichier.csv       export CSV
--tlds fr,com,org       TLDs à tester
--tld-groups a,b        groupes TLD prédéfinis à utiliser
--list-tld-groups       liste les groupes TLD disponibles
--iana-tlds             teste tous les TLDs actuellement autorisés par l'IANA
--tlds-file fichier     charge une liste locale de TLDs
--timeout 3             timeout réseau par opération
--delay 0               délai entre domaines
--max-results N         limite optionnelle de candidats
--workers 4             nombre de domaines testés en parallèle
--no-ping               désactive ICMP ping
--no-combinations       désactive les sous-combinaisons de mots
--keep-stopwords        conserve les mots comme et, de, la
--no-single-words       ne teste pas les mots isolés
--exclude-words a,b     exclut certains mots isolés
--dry-run               affiche les domaines générés sans requêtes réseau
--progress              force la progression si le terminal n'est pas détecté
--no-progress           désactive la barre de progression
--no-links              désactive les liens cliquables en console
--verbose               affiche les erreurs et domaines injoignables
```

## Classifications

| Statut | Signification |
| --- | --- |
| `unreachable` | Pas de résolution DNS exploitable |
| `dns_only` | DNS OK, mais pas de réponse HTTP/HTTPS ni ping utile |
| `ping_only` | DNS OK et ping OK, mais pas de réponse HTTP/HTTPS |
| `http_alive` | Réponse HTTP/HTTPS technique, sans titre HTML exploitable |
| `web_site` | Réponse HTTP/HTTPS avec titre HTML |

## Sortie JSON

```bash
URLINT baguette tradition --tlds fr,com --max-results 4 --no-ping --json
```

```json
[
  {
    "domain": "baguettetradition.fr",
    "classification": "dns_only",
    "dns_resolves": true,
    "ips": ["203.0.113.11"],
    "dns_error": null,
    "ping_alive": null,
    "ping_error": null,
    "http_alive": false,
    "protocol": null,
    "http_status": null,
    "title": null,
    "server": null,
    "content_type": null,
    "redirect": false,
    "redirect_location": null,
    "http_error": "http_unreachable"
  }
]
```

## Export CSV

```bash
URLINT baguette tradition --tlds fr,com --max-results 4 --no-ping --csv results.csv
```

```csv
domain,classification,dns_resolves,ips,dns_error,ping_alive,ping_error,http_alive,protocol,http_status,title,server,content_type,redirect,redirect_location,http_error
baguettetradition.fr,dns_only,True,203.0.113.11,,,,False,,,,,False,,http_unreachable
baguette-tradition.fr,web_site,True,203.0.113.10,,,,True,https,200,Baguette Tradition,nginx,text/html; charset=utf-8,False,,
```

## Comportement Réseau

`URLINT` reste volontairement léger :

- teste uniquement les domaines racine ;
- ne scanne pas de chemins ;
- ne suit pas automatiquement les redirects ;
- ne contourne pas les protections anti-bot ;
- utilise un User-Agent explicite : `URLINT-osint-light/1.0` ;
- limite le `GET` HTML à 64 KiB ;
- utilise `httpx.Client` avec pooling par worker ;
- garde une concurrence bornée avec `--workers`.

Les liens cliquables en console sont activés automatiquement quand `URLINT` détecte une sortie terminal. Sur les terminaux compatibles, `URLINT` utilise les hyperlinks ANSI OSC 8 pour garder la colonne `Domain` propre. Sur WSL ou les terminaux moins prévisibles, il affiche une URL visible comme `https://example.com`, plus souvent reconnue automatiquement par le terminal. Utilisez `--no-links` pour revenir à un affichage texte simple.

## Usage Responsable

Cet outil est conçu pour de l'OSINT défensif, de l'inventaire et du triage léger.

Recommandations :

- utilisez `--dry-run` avant les scans larges ;
- ajoutez `--max-results` pour borner volontairement le périmètre ;
- utilisez `--delay 1` ou plus avec `--iana-tlds` ou des gros groupes ;
- gardez `--workers` modéré ;
- ne lancez pas de boucles massives autour de l'outil ;
- n'utilisez pas `URLINT` pour contourner des protections, rate limits ou CAPTCHA.

## Dépendances

`URLINT` utilise :

- `httpx` pour HTTP/HTTPS ;
- la bibliothèque standard Python pour DNS, ping, CLI, JSON et CSV.

L'installation via `pip install .` ou `pip install -e .` installe automatiquement `httpx`.
