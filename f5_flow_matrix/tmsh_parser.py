"""Parseur générique du format de configuration tmsh (bigip.conf / SCF).

Le format tmsh est un arbre d'objets à accolades :

    ltm virtual /Common/vs_web_443 {
        destination /Common/10.10.10.100:443
        ip-protocol tcp
        pool /Common/pool_web_80
        profiles {
            /Common/http { }
            /Common/clientssl { context clientside }
        }
    }

Ce module ne connaît rien de la sémantique F5 : il transforme le texte en un
arbre de `Block` (objet avec des tokens d'en-tête + des enfants) et de `Leaf`
(ligne clé/valeur simple). L'interprétation métier (virtual server, pool,
règle firewall, ...) se fait dans `extract.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional, Union


@dataclass
class Leaf:
    """Une ligne simple sans accolade, ex: `ip-protocol tcp`."""

    tokens: list[str]

    @property
    def key(self) -> str:
        return self.tokens[0] if self.tokens else ""

    @property
    def value(self) -> str:
        return " ".join(self.tokens[1:])


@dataclass
class Block:
    """Un objet avec des accolades, ex: `ltm virtual /Common/vs1 { ... }`."""

    header: list[str]
    children: list["Statement"] = field(default_factory=list)

    @property
    def type_tuple(self) -> tuple[str, ...]:
        """Les tokens de type (tout sauf le nom final s'il existe)."""
        name_idx = self._name_index()
        if name_idx is None:
            return tuple(self.header)
        return tuple(self.header[:name_idx])

    @property
    def name(self) -> Optional[str]:
        name_idx = self._name_index()
        if name_idx is None:
            return None
        return self.header[name_idx]

    def _name_index(self) -> Optional[int]:
        # En-tête à un seul token (ex: nom de règle firewall, entrée de liste
        # sans partition) : ce token EST le nom, qu'il commence par "/" ou non.
        if len(self.header) == 1:
            return 0
        # Sinon, heuristique : le nom d'objet F5 est le dernier token de
        # l'en-tête qui commence par "/" (chemin de partition, ex: /Common/vs1).
        for i in range(len(self.header) - 1, -1, -1):
            if self.header[i].startswith("/"):
                return i
        return None

    def child_blocks(self, key: str) -> list["Block"]:
        """Enfants directs qui sont des Block dont header[0] == key."""
        return [
            c for c in self.children
            if isinstance(c, Block) and c.header and c.header[0] == key
        ]

    def child_block(self, key: str) -> Optional["Block"]:
        blocks = self.child_blocks(key)
        return blocks[0] if blocks else None

    def leaves(self) -> dict[str, list[str]]:
        """Dict key -> liste de valeurs pour tous les Leaf enfants directs."""
        result: dict[str, list[str]] = {}
        for c in self.children:
            if isinstance(c, Leaf):
                result.setdefault(c.key, []).append(c.value)
        return result

    def leaf_value(self, key: str, default: Optional[str] = None) -> Optional[str]:
        for c in self.children:
            if isinstance(c, Leaf) and c.key == key:
                return c.value
        return default

    def has_flag(self, key: str) -> bool:
        """Pour les lignes booléennes sans valeur, ex: `vlans-enabled`."""
        return any(
            isinstance(c, Leaf) and c.key == key for c in self.children
        )


Statement = Union[Block, Leaf]


def _tokenize(text: str) -> list[str]:
    """Découpe le texte en tokens ; '\\n' marque une fin de ligne logique."""
    tokens: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            tokens.append("\n")
            continue
        i, n = 0, len(line)
        while i < n:
            c = line[i]
            if c.isspace():
                i += 1
                continue
            if c in "{}":
                tokens.append(c)
                i += 1
                continue
            if c == '"':
                j = i + 1
                buf = []
                while j < n:
                    if line[j] == "\\" and j + 1 < n:
                        # Guillemet ou backslash échappé (ex: rule "...\"...\""
                        # dans les signatures ASM/DoS) : ne referme pas la chaîne.
                        buf.append(line[j + 1])
                        j += 2
                        continue
                    if line[j] == '"':
                        break
                    buf.append(line[j])
                    j += 1
                tokens.append("".join(buf))
                i = j + 1
                continue
            j = i
            while j < n and not line[j].isspace() and line[j] not in "{}":
                j += 1
            tokens.append(line[i:j])
            i = j
        tokens.append("\n")
    return tokens


def _parse_statements(tokens: list[str], pos: int) -> tuple[list[Statement], int]:
    stmts: list[Statement] = []
    header: list[str] = []
    n = len(tokens)
    while pos < n:
        t = tokens[pos]
        if t == "}":
            if header:
                stmts.append(Leaf(header))
                header = []
            return stmts, pos
        if t == "{":
            pos += 1
            children, pos = _parse_statements(tokens, pos)
            if pos < n and tokens[pos] == "}":
                pos += 1
            stmts.append(Block(header, children))
            header = []
            continue
        if t == "\n":
            if header:
                stmts.append(Leaf(header))
                header = []
            pos += 1
            continue
        header.append(t)
        pos += 1
    if header:
        stmts.append(Leaf(header))
    return stmts, pos


def parse_config(text: str) -> list[Statement]:
    """Parse le contenu d'un fichier bigip.conf/SCF en liste de Statement."""
    tokens = _tokenize(text)
    stmts, pos = _parse_statements(tokens, 0)
    if pos != len(tokens):
        raise ValueError(
            f"Erreur de parsing tmsh : accolade fermante en trop ou manquante "
            f"(position token {pos}/{len(tokens)})"
        )
    return stmts


def iter_objects(
    statements: list[Statement], *type_prefix: str
) -> Iterator[Block]:
    """Itère sur les Block de premier niveau dont le type commence par type_prefix.

    Exemple : iter_objects(tree, "ltm", "virtual") pour tous les virtual servers.
    """
    prefix = tuple(type_prefix)
    for stmt in statements:
        if isinstance(stmt, Block) and stmt.type_tuple[: len(prefix)] == prefix:
            yield stmt


def flatten_tokens(stmt: Statement) -> list[str]:
    """Aplatit récursivement tous les tokens d'un Block/Leaf.

    Utile pour une recherche heuristique de références (ex: retrouver le nom
    d'un data-group cité dans le corps TCL d'une iRule, qu'on ne cherche pas
    à interpréter sémantiquement, seulement à indexer par mots).
    """
    if isinstance(stmt, Leaf):
        return list(stmt.tokens)
    tokens = list(stmt.header)
    for c in stmt.children:
        tokens.extend(flatten_tokens(c))
    return tokens


def strip_partition(path: str) -> str:
    """/Common/vs1 -> vs1 ; laisse tel quel si pas de '/'."""
    return path.rsplit("/", 1)[-1] if path else path


def split_addr_port(value: str) -> tuple[str, Optional[str]]:
    """Sépare une valeur F5 'adresse:port' ou 'adresse.port' (IPv6) en (addr, port).

    Le nom peut être préfixé par une partition (/Common/...), qui est retirée.
    Retourne (adresse, None) si aucun port n'est présent.
    """
    name = strip_partition(value)
    # IPv6 : F5 sépare le port par un '.' car ':' fait partie de l'adresse.
    if name.count(":") > 1:
        if "." in name:
            addr, _, port = name.rpartition(".")
            return addr, port
        return name, None
    if ":" in name:
        addr, _, port = name.rpartition(":")
        return addr, port
    return name, None
