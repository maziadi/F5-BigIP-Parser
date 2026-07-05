"""Extraction des objets F5 métier (LTM, SNAT, AFM, GTM) depuis l'arbre tmsh."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .tmsh_parser import (
    Block,
    Leaf,
    flatten_tokens,
    iter_objects,
    parse_config,
    split_addr_port,
    strip_partition,
)


def _list_names(container: Optional[Block]) -> list[str]:
    """Noms des enfants d'un bloc-liste, que ce soient des Block ou des Leaf.

    Les listes tmsh s'écrivent soit avec des accolades par élément
    (`profiles { /Common/http { } }`), soit en simples lignes
    (`members { /Common/10.10.10.200 }`).
    """
    if container is None:
        return []
    names = []
    for c in container.children:
        if isinstance(c, Block):
            names.append(c.name)
        elif isinstance(c, Leaf):
            names.append(c.key)
    return names


@dataclass
class Node:
    name: str
    address: str
    is_fqdn: bool = False


@dataclass
class PoolMember:
    name: str
    address: str
    port: Optional[str]
    is_fqdn: bool = False


@dataclass
class Pool:
    name: str
    members: list[PoolMember]
    monitor: Optional[str]
    lb_mode: Optional[str]


@dataclass
class VirtualServer:
    name: str
    destination_address: Optional[str]
    destination_port: Optional[str]
    ip_protocol: Optional[str]
    mask: Optional[str]
    pool: Optional[str]
    source: Optional[str]
    snat_type: Optional[str]
    snat_pool: Optional[str]
    vlans: list[str]
    vlans_disabled: bool
    profiles: list[str]
    is_forwarding: bool
    description: Optional[str]
    enabled: bool = True
    irules: list[str] = field(default_factory=list)


@dataclass
class TrafficMatchingCriteria:
    name: str
    destination_address_inline: Optional[str]
    destination_address_list: Optional[str]
    destination_port_inline: Optional[str]
    destination_port_list: Optional[str]
    protocol: Optional[str]
    source_address_inline: Optional[str]
    source_address_list: Optional[str]


@dataclass
class AddressOrPortList:
    name: str
    values: list[str]


@dataclass
class VirtualAddress:
    name: str
    address: str
    enabled: bool = True
    description: Optional[str] = None


@dataclass
class DataGroup:
    name: str
    type: Optional[str]
    records: dict[str, Optional[str]] = field(default_factory=dict)
    referenced_by_irules: list[str] = field(default_factory=list)


@dataclass
class SnatPool:
    name: str
    addresses: list[str]


@dataclass
class SnatTranslation:
    name: str
    address: str


@dataclass
class FirewallRule:
    container_type: str  # "rule-list" ou "policy"
    container_name: str
    name: str
    action: Optional[str]
    protocol: Optional[str]
    log: bool
    src_addresses: list[str]
    src_ports: list[str]
    dst_addresses: list[str]
    dst_ports: list[str]
    ref_rule_list: Optional[str]


@dataclass
class GtmServer:
    name: str
    virtual_servers: dict[str, tuple[Optional[str], Optional[str]]]


@dataclass
class GtmPoolMember:
    server_ref: str
    vs_ref: str


@dataclass
class GtmPool:
    name: str
    record_type: Optional[str]
    members: list[GtmPoolMember]
    lb_mode: Optional[str]


@dataclass
class GtmWideIP:
    name: str
    record_type: Optional[str]
    pools: list[str]


@dataclass
class ParsedDevice:
    device_label: str
    hostname: Optional[str]
    nodes: dict[str, Node] = field(default_factory=dict)
    pools: dict[str, Pool] = field(default_factory=dict)
    virtuals: dict[str, VirtualServer] = field(default_factory=dict)
    virtual_addresses: dict[str, VirtualAddress] = field(default_factory=dict)
    data_groups: dict[str, DataGroup] = field(default_factory=dict)
    snatpools: dict[str, SnatPool] = field(default_factory=dict)
    snat_translations: dict[str, SnatTranslation] = field(default_factory=dict)
    firewall_rules: list[FirewallRule] = field(default_factory=list)
    gtm_servers: dict[str, GtmServer] = field(default_factory=dict)
    gtm_pools: dict[str, GtmPool] = field(default_factory=dict)
    gtm_wideips: list[GtmWideIP] = field(default_factory=list)


def _extract_nodes(tree) -> dict[str, Node]:
    nodes = {}
    for b in iter_objects(tree, "ltm", "node"):
        fqdn_block = b.child_block("fqdn")
        if fqdn_block:
            addr = fqdn_block.leaf_value("name") or strip_partition(b.name)
            nodes[b.name] = Node(name=b.name, address=addr, is_fqdn=True)
        else:
            addr = b.leaf_value("address") or strip_partition(b.name)
            nodes[b.name] = Node(name=b.name, address=addr)
    return nodes


def _extract_pools(tree) -> dict[str, Pool]:
    pools = {}
    for b in iter_objects(tree, "ltm", "pool"):
        members = []
        members_block = b.child_block("members")
        if members_block:
            for m in members_block.children:
                if not isinstance(m, Block):
                    continue
                addr, port = split_addr_port(m.name)
                addr = m.leaf_value("address") or addr
                is_fqdn = m.child_block("fqdn") is not None
                members.append(PoolMember(name=m.name, address=addr, port=port, is_fqdn=is_fqdn))
        pools[b.name] = Pool(
            name=b.name,
            members=members,
            monitor=b.leaf_value("monitor"),
            lb_mode=b.leaf_value("load-balancing-mode"),
        )
    return pools


def _extract_traffic_matching_criteria(tree) -> dict[str, TrafficMatchingCriteria]:
    tmcs = {}
    for b in iter_objects(tree, "ltm", "traffic-matching-criteria"):
        tmcs[b.name] = TrafficMatchingCriteria(
            name=b.name,
            destination_address_inline=b.leaf_value("destination-address-inline"),
            destination_address_list=b.leaf_value("destination-address-list"),
            destination_port_inline=b.leaf_value("destination-port-inline"),
            destination_port_list=b.leaf_value("destination-port-list"),
            protocol=b.leaf_value("protocol"),
            source_address_inline=b.leaf_value("source-address-inline"),
            source_address_list=b.leaf_value("source-address-list"),
        )
    return tmcs


def _extract_address_or_port_lists(tree, *type_prefixes: tuple[str, ...]) -> dict[str, AddressOrPortList]:
    """Extrait les objets 'address-list'/'port-list', quel que soit le module
    tmsh sous lequel ils sont rangés (net / ltm / security firewall selon
    version F5). Résout aussi les listes imbriquées (une liste peut inclure
    une autre liste) quand toutes les définitions sont présentes."""
    lists: dict[str, AddressOrPortList] = {}
    raw_members: dict[str, list[str]] = {}
    for prefix in type_prefixes:
        for b in iter_objects(tree, *prefix):
            entries_block = b.child_block("addresses") or b.child_block("ports")
            raw_members[b.name] = _list_names(entries_block)

    def resolve(name: str, seen: set) -> list[str]:
        if name in lists:
            return lists[name].values
        if name not in raw_members or name in seen:
            return []
        seen.add(name)
        values = []
        for entry in raw_members[name]:
            if entry in raw_members:
                values.extend(resolve(entry, seen))
            else:
                values.append(entry)
        return values

    for name in raw_members:
        lists[name] = AddressOrPortList(name=name, values=resolve(name, set()))
    return lists


def _resolve_tmc_side(
    inline: Optional[str],
    list_ref: Optional[str],
    lists: dict[str, AddressOrPortList],
) -> Optional[str]:
    if list_ref:
        resolved = lists.get(list_ref)
        if resolved and resolved.values:
            return ", ".join(resolved.values)
        return f"(liste non résolue dans ce fichier: {strip_partition(list_ref)})"
    return inline


def _extract_virtuals(
    tree,
    tmcs: dict[str, TrafficMatchingCriteria],
    address_lists: dict[str, AddressOrPortList],
    port_lists: dict[str, AddressOrPortList],
) -> dict[str, VirtualServer]:
    virtuals = {}
    for b in iter_objects(tree, "ltm", "virtual"):
        dest = b.leaf_value("destination")
        tmc_name = b.leaf_value("traffic-matching-criteria")
        tmc = tmcs.get(tmc_name) if tmc_name else None
        if dest:
            addr, port = split_addr_port(dest)
            protocol = b.leaf_value("ip-protocol")
            source = b.leaf_value("source")
        elif tmc:
            addr = _resolve_tmc_side(tmc.destination_address_inline, tmc.destination_address_list, address_lists)
            port = _resolve_tmc_side(tmc.destination_port_inline, tmc.destination_port_list, port_lists)
            protocol = tmc.protocol
            source = _resolve_tmc_side(tmc.source_address_inline, tmc.source_address_list, address_lists)
        else:
            addr, port = None, None
            protocol = b.leaf_value("ip-protocol")
            source = b.leaf_value("source")
        sat = b.child_block("source-address-translation")
        snat_type = sat.leaf_value("type") if sat else None
        snat_pool = sat.leaf_value("pool") if sat else None
        vlans = _list_names(b.child_block("vlans"))
        profiles = _list_names(b.child_block("profiles"))
        irules = _list_names(b.child_block("rules"))
        virtuals[b.name] = VirtualServer(
            name=b.name,
            destination_address=addr,
            destination_port=port,
            ip_protocol=protocol,
            mask=b.leaf_value("mask"),
            pool=b.leaf_value("pool"),
            source=source,
            snat_type=snat_type,
            snat_pool=snat_pool,
            vlans=vlans,
            vlans_disabled=b.has_flag("vlans-disabled"),
            profiles=profiles,
            is_forwarding=b.leaf_value("translate-address") == "disabled",
            description=b.leaf_value("description"),
            enabled=not b.has_flag("disabled"),
            irules=irules,
        )
    return virtuals


def _extract_virtual_addresses(tree) -> dict[str, VirtualAddress]:
    vaddrs = {}
    for b in iter_objects(tree, "ltm", "virtual-address"):
        addr = b.leaf_value("address") or strip_partition(b.name)
        vaddrs[b.name] = VirtualAddress(
            name=b.name,
            address=addr,
            enabled=not b.has_flag("disabled"),
            description=b.leaf_value("description"),
        )
    return vaddrs


def _extract_data_groups(tree) -> dict[str, DataGroup]:
    groups = {}
    for b in iter_objects(tree, "ltm", "data-group"):
        records_block = b.child_block("records")
        records: dict[str, Optional[str]] = {}
        if records_block:
            for r in records_block.children:
                if isinstance(r, Block):
                    records[r.name] = r.leaf_value("data")
                elif isinstance(r, Leaf):
                    records[r.key] = r.value or None
        groups[b.name] = DataGroup(name=b.name, type=b.leaf_value("type"), records=records)
    return groups


def _link_irule_datagroup_references(tree, data_groups: dict[str, DataGroup]) -> None:
    """Recherche heuristique (par sous-chaîne) des data-groups cités dans le
    corps TCL de chaque iRule. On n'interprète pas le TCL : on indexe juste
    les tokens de la iRule et on regarde si un nom de data-group y apparaît.
    """
    if not data_groups:
        return
    candidates = {name: (name, strip_partition(name)) for name in data_groups}
    for rule_block in iter_objects(tree, "ltm", "rule"):
        tokens = flatten_tokens(rule_block)
        haystack = " ".join(tokens)
        for full_name, (full, bare) in candidates.items():
            if full in haystack or bare in haystack:
                data_groups[full_name].referenced_by_irules.append(strip_partition(rule_block.name))


def _extract_snatpools(tree) -> dict[str, SnatPool]:
    pools = {}
    for b in iter_objects(tree, "ltm", "snatpool"):
        addrs = _list_names(b.child_block("members"))
        pools[b.name] = SnatPool(name=b.name, addresses=[strip_partition(a) for a in addrs])
    return pools


def _extract_snat_translations(tree) -> dict[str, SnatTranslation]:
    out = {}
    for b in iter_objects(tree, "ltm", "snat-translation"):
        addr = b.leaf_value("address") or strip_partition(b.name)
        out[b.name] = SnatTranslation(name=b.name, address=addr)
    return out


def _extract_firewall_rule_block(rule_block: Block, container_type: str, container_name: str) -> FirewallRule:
    src = rule_block.child_block("source")
    dst = rule_block.child_block("destination")
    log_val = rule_block.leaf_value("log")
    return FirewallRule(
        container_type=container_type,
        container_name=container_name,
        name=rule_block.name,
        action=rule_block.leaf_value("action"),
        protocol=rule_block.leaf_value("ip-protocol"),
        log=(log_val in ("yes", "enabled")) if log_val is not None else False,
        src_addresses=_list_names(src.child_block("addresses")) if src else [],
        src_ports=_list_names(src.child_block("ports")) if src else [],
        dst_addresses=_list_names(dst.child_block("addresses")) if dst else [],
        dst_ports=_list_names(dst.child_block("ports")) if dst else [],
        ref_rule_list=rule_block.leaf_value("rule-list"),
    )


def _extract_firewall_rules(tree) -> list[FirewallRule]:
    rules = []
    for container_type in ("rule-list", "policy"):
        for b in iter_objects(tree, "security", "firewall", container_type):
            rules_block = b.child_block("rules")
            if not rules_block:
                continue
            for r in rules_block.children:
                if isinstance(r, Block):
                    rules.append(_extract_firewall_rule_block(r, container_type, b.name))
    return rules


def _extract_gtm_servers(tree) -> dict[str, GtmServer]:
    servers = {}
    for b in iter_objects(tree, "gtm", "server"):
        vs_block = b.child_block("virtual-servers")
        vs_map = {}
        if vs_block:
            for vsb in vs_block.children:
                if not isinstance(vsb, Block):
                    continue
                dest = vsb.leaf_value("destination")
                addr, port = split_addr_port(dest) if dest else (None, None)
                vs_map[vsb.name] = (addr, port)
        servers[b.name] = GtmServer(name=b.name, virtual_servers=vs_map)
    return servers


def _extract_gtm_pools(tree) -> dict[str, GtmPool]:
    pools = {}
    for b in iter_objects(tree, "gtm", "pool"):
        record_type = b.type_tuple[2] if len(b.type_tuple) >= 3 else None
        members = []
        members_block = b.child_block("members")
        for ref in _list_names(members_block):
            server_ref, sep, vs_ref = ref.rpartition(":")
            if sep:
                members.append(GtmPoolMember(server_ref=server_ref, vs_ref=vs_ref))
        pools[b.name] = GtmPool(
            name=b.name,
            record_type=record_type,
            members=members,
            lb_mode=b.leaf_value("load-balancing-mode"),
        )
    return pools


def _extract_gtm_wideips(tree) -> list[GtmWideIP]:
    wideips = []
    for b in iter_objects(tree, "gtm", "wideip"):
        record_type = b.type_tuple[2] if len(b.type_tuple) >= 3 else None
        pools = _list_names(b.child_block("pools"))
        wideips.append(GtmWideIP(name=b.name, record_type=record_type, pools=pools))
    return wideips


def _extract_hostname(tree) -> Optional[str]:
    for b in iter_objects(tree, "sys", "global-settings"):
        hostname = b.leaf_value("hostname")
        if hostname:
            return hostname
    return None


def parse_device(text: str, device_label: str) -> ParsedDevice:
    """Parse le contenu d'un fichier bigip.conf/SCF en objets métier F5."""
    tree = parse_config(text)
    data_groups = _extract_data_groups(tree)
    _link_irule_datagroup_references(tree, data_groups)
    tmcs = _extract_traffic_matching_criteria(tree)
    address_lists = _extract_address_or_port_lists(
        tree, ("net", "address-list"), ("ltm", "address-list"), ("security", "firewall", "address-list")
    )
    port_lists = _extract_address_or_port_lists(
        tree, ("net", "port-list"), ("ltm", "port-list"), ("security", "firewall", "port-list")
    )
    return ParsedDevice(
        device_label=device_label,
        hostname=_extract_hostname(tree),
        nodes=_extract_nodes(tree),
        pools=_extract_pools(tree),
        virtuals=_extract_virtuals(tree, tmcs, address_lists, port_lists),
        virtual_addresses=_extract_virtual_addresses(tree),
        data_groups=data_groups,
        snatpools=_extract_snatpools(tree),
        snat_translations=_extract_snat_translations(tree),
        firewall_rules=_extract_firewall_rules(tree),
        gtm_servers=_extract_gtm_servers(tree),
        gtm_pools=_extract_gtm_pools(tree),
        gtm_wideips=_extract_gtm_wideips(tree),
    )
