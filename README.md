# F5 Flow Matrix

Génère une matrice de flux réseau à partir de fichiers de configuration F5 BIG-IP (`bigip.conf` / SCF), pour cartographier les flux entrants vers un datacenter on-prem.

## Principe général

Un fichier `bigip.conf` est un export tmsh : un arbre d'objets à accolades (virtual servers, pools, nodes, règles firewall, etc.). Le pipeline se déroule en trois étapes :

1. **Parsing** : le texte brut est transformé en arbre générique (`Block`/`Leaf`), sans connaissance de la sémantique F5.
2. **Extraction** : l'arbre générique est interprété pour produire des objets métier typés (virtual server, pool, node, règle firewall, ...).
3. **Construction de la matrice** : les objets métier sont mis en relation (client → VIP → pool → serveur réel) pour produire des lignes de flux, puis exportées en CSV/XLSX.

## Composants

### `f5_flow_matrix/tmsh_parser.py`

Parseur générique du format tmsh. Ne connaît rien de la sémantique F5 : il transforme le texte en un arbre de deux types de nœuds :

- `Leaf` : une ligne simple sans accolade (`ip-protocol tcp`).
- `Block` : un objet avec accolades (`ltm virtual /Common/vs1 { ... }`), avec ses enfants (`Leaf`/`Block`).

Points d'attention gérés par le tokenizer :
- guillemets échappés dans les valeurs (`rule "headercontent:\"texte\";"`), fréquents dans les signatures ASM/DoS — un échappement mal géré désynchronise le comptage de guillemets et corrompt silencieusement tout le reste du fichier ;
- adresses IPv6 (séparateur `.` avant le port au lieu de `:`) ;
- listes tmsh écrites soit avec une accolade par élément (`profiles { /Common/http { } }`), soit en lignes simples (`members { /Common/10.10.10.200 }`).

Fonctions clés :
- `parse_config(text)` : parse un fichier entier en liste de `Statement` de premier niveau.
- `iter_objects(tree, *type_prefix)` : itère sur les objets de premier niveau dont le type correspond (ex. `iter_objects(tree, "ltm", "virtual")`).
- `flatten_tokens(stmt)` : aplatit récursivement tous les tokens d'un bloc, utilisé pour une recherche heuristique par sous-chaîne (ex. retrouver un data-group cité dans le corps TCL d'une iRule, sans interpréter le TCL).
- `split_addr_port(value)` / `strip_partition(path)` : utilitaires de parsing des valeurs F5 (`/Common/10.1.1.10:80` → `("10.1.1.10", "80")`).

### `f5_flow_matrix/extract.py`

Interprète l'arbre générique pour produire des dataclasses métier, regroupées dans un `ParsedDevice` par fichier de config traité :

| Objet F5 (tmsh)                                            | Dataclass              | Contenu extrait |
|--------------------------------------------------------------|-------------------------|-----------------|
| `ltm node`                                                  | `Node`                 | adresse, détection FQDN (`fqdn { name ... }`) |
| `ltm pool`                                                  | `Pool`, `PoolMember`   | membres (adresse:port), monitor, mode de répartition |
| `ltm virtual`                                                | `VirtualServer`        | destination, protocole, pool, source, SNAT, VLANs, profils, iRules, statut enabled/disabled |
| `ltm traffic-matching-criteria`                             | `TrafficMatchingCriteria` | destination/source/protocole quand ils ne sont pas inline sur le virtual server (modèle F5 récent) |
| `net`/`ltm`/`security firewall address-list` et `port-list` | `AddressOrPortList`     | listes réutilisables référencées par une TMC, avec résolution récursive |
| `ltm virtual-address`                                        | `VirtualAddress`        | adresse flottante déclarée, statut enabled/disabled |
| `ltm snatpool`, `ltm snat-translation`                      | `SnatPool`, `SnatTranslation` | adresses de translation source |
| `ltm data-group internal`                                    | `DataGroup`             | table clé → valeur, avec les iRules qui la référencent (recherche heuristique) |
| `security firewall rule-list`, `security firewall policy`  | `FirewallRule`          | action, protocole, adresses/ports source et destination, log |
| `gtm server`, `gtm pool`, `gtm wideip`                      | `GtmServer`, `GtmPool`, `GtmWideIP` | résolution DNS/GSLB multi-datacenter |

Cas particuliers gérés :
- **`traffic-matching-criteria`** : sur les versions récentes de BIG-IP, un virtual server peut ne pas avoir de `destination` inline et référencer un objet `ltm traffic-matching-criteria` séparé, lui-même pouvant renvoyer vers une `address-list`/`port-list` plutôt qu'une adresse littérale. `extract.py` résout cette chaîne de références ; si une liste n'est pas définie dans le fichier fourni, le champ correspondant affiche explicitement `(liste non résolue dans ce fichier: NOM)` plutôt qu'une valeur vide.
- **Nodes/pool members FQDN** : un nœud ou un membre de pool peut être défini par nom de domaine (`fqdn { name ... }`) plutôt que par IP statique. Le champ `is_fqdn` est positionné pour que la matrice de flux le signale (IP réelle dépendante de la résolution DNS au moment du flux).
- **Data-groups référencés par iRule** : les iRules (`ltm rule`) contiennent du TCL qui n'est pas interprété sémantiquement. `_link_irule_datagroup_references` fait une recherche par sous-chaîne du nom de chaque data-group dans les tokens aplatis de chaque iRule, pour donner une piste de traçabilité sans prétendre à une résolution exacte du routage applicatif.

### `f5_flow_matrix/flow_matrix.py`

Met en relation les objets extraits pour produire des lignes de flux normalisées (une ligne = un flux). Cinq familles de lignes (`FlowType`) :

| FlowType        | Sens du flux                                  | Construit à partir de |
|-----------------|------------------------------------------------|------------------------|
| `Ingress-LB`    | client → VIP (ce qui entre dans le F5)         | `ltm virtual` |
| `Backend-LB`    | F5/SNAT → membre de pool (le serveur réel)     | `ltm virtual` + `ltm pool` + SNAT |
| `Firewall-Rule` | règle AFM explicite                             | `security firewall rule-list`/`policy` |
| `GTM-DNS`       | client DNS → datacenter résolu par GSLB        | `gtm wideip` + `gtm pool` + `gtm server` |
| `VIP-Orphan`    | adresse flottante déclarée mais non utilisée   | `ltm virtual-address` sans `ltm virtual` correspondant |

Résolution du flux backend (`Backend-LB`) selon le mode SNAT du virtual server :
- `automap` → source affichée comme "Self-IP F5 (automap)" ;
- `snat` + pool → adresses du `ltm snatpool` référencé ;
- `none` ou absent → IP client d'origine préservée (comportement par défaut F5 sans configuration explicite).

Chaque ligne porte une colonne **`NeedsReview`**, renseignée quand le flux affiché peut différer du flux réel :
- virtual server désactivé (`disabled`) ;
- virtual server piloté par une ou plusieurs iRules (logique TCL non interprétée) ;
- membre de pool résolu par FQDN (IP non figée dans la config) ;
- adresse destination/source dépendant d'une address-list absente du fichier ;
- VIP orpheline.

`build_flow_matrix(devices)` consolide toutes ces lignes pour un ou plusieurs devices. `build_datagroup_rows(devices)` produit séparément une table de référence des data-groups (non mêlée à la matrice de flux, car ce ne sont pas des flux mais des tables de correspondance utilisées par les iRules).

### `f5_flow_matrix/export.py`

Écrit les lignes produites par `flow_matrix.py` en CSV et XLSX :
- **CSV** : délimiteur `;`, encodage `utf-8-sig` (compatible Excel FR).
- **XLSX** : jusqu'à 3 feuilles —
  1. `Matrice de flux` : toutes les lignes, en-tête figé, filtres automatiques, coloration par `FlowType` et surlignage des cellules `NeedsReview` non vides ;
  2. `Points d'attention` : sous-ensemble des lignes dont `NeedsReview` est renseigné, pour une revue manuelle rapide ;
  3. `DataGroups (ref. iRules)` : table de référence des data-groups (générée seulement si le fichier en contient).

### `generate_flow_matrix.py`

CLI qui orchestre le pipeline : lecture des fichiers d'entrée → `parse_device` → `build_flow_matrix` / `build_datagroup_rows` → écriture CSV/XLSX. Accepte plusieurs fichiers et/ou dossiers en une seule exécution, avec consolidation dans une seule matrice (colonne `Device`/`Hostname` par ligne).

## Limites connues

- Les iRules (`ltm rule`) ne sont pas interprétées : si une iRule redirige dynamiquement le trafic (choix de pool applicatif, réécriture d'URL, etc.), seul le pool par défaut du virtual server apparaît dans la matrice. La colonne `NeedsReview` et la feuille `DataGroups` donnent des pistes pour une vérification manuelle, sans se substituer à elle.
- Les objets référencés mais absents du fichier fourni (pool, address-list, rule-list, GTM server) sont signalés explicitement (`introuvable`, `non résolu dans ce fichier`) plutôt que silencieusement ignorés.
- Le parseur est générique au format tmsh : il ne valide pas la cohérence sémantique F5 (ex. une iRule syntaxiquement valide mais absurde d'un point de vue métier ne sera pas détectée comme telle).

## Lancer le script

### Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Usage

```bash
python generate_flow_matrix.py --input <fichier_ou_dossier> [<fichier_ou_dossier> ...] [options]
```

Exemples :

```bash
# Un seul fichier de config
python generate_flow_matrix.py --input bigip.conf

# Plusieurs fichiers, avec des labels explicites par device/datacenter
python generate_flow_matrix.py \
  --input bigip_dc1.conf bigip_dc2.conf \
  --device-labels DC1 DC2 \
  --output-dir output

# Un dossier entier (tous les *.conf/*.scf qu'il contient)
python generate_flow_matrix.py --input ./configs/
```

Options principales :

| Option              | Description |
|----------------------|--------------|
| `--input`, `-i`      | Un ou plusieurs fichiers `bigip.conf`/SCF, et/ou dossiers les contenant (obligatoire). |
| `--device-labels`    | Labels à associer à chaque fichier d'entrée, dans le même ordre (par défaut : nom du fichier). |
| `--output-dir`, `-o` | Dossier de sortie (par défaut : `./output`). |
| `--basename`         | Préfixe des fichiers générés (par défaut : `matrice_de_flux`). |
| `--format`           | `csv`, `xlsx` ou `both` (par défaut : `both`). |

Sortie produite dans `--output-dir` :
- `<basename>.csv` et/ou `<basename>.xlsx` : la matrice de flux consolidée.
- `<basename>_datagroups.csv` (CSV uniquement, en complément de la feuille XLSX) : généré seulement si des data-groups sont présents dans au moins un fichier traité.

Le dossier `samples/` contient des exemples de fichiers de config synthétiques (`bigip_sample_dc1.conf`, `bigip_sample_dc2.conf`) permettant de tester le pipeline sans fichier de production :

```bash
python generate_flow_matrix.py --input samples/bigip_sample_dc1.conf samples/bigip_sample_dc2.conf --device-labels DC1 DC2
```
