"""Construction de la matrice de flux à partir des objets F5 extraits.

Cinq familles de lignes sont produites :

- Ingress-LB      : client -> VIP (virtual server), ce qui "entre" dans le F5.
- Backend-LB      : F5/SNAT -> membre de pool (le "vrai" serveur derrière la VIP).
- Firewall-Rule   : règles AFM (security firewall rule-list / policy), si présentes.
- GTM-DNS         : résolution GTM/DNS wideip -> pool -> virtual server + datacenter.
- VIP-Orphan      : adresses "ltm virtual-address" déclarées mais non utilisées comme
                     destination d'un virtual server dans ce même fichier (à vérifier).

Une colonne NeedsReview signale les lignes dont le flux réel peut différer de ce qui
est indiqué ici : VS désactivé, VS piloté par une ou plusieurs iRules (logique TCL non
interprétée), membre de pool résolu par FQDN (IP réelle dépendante du DNS), ou VIP
orpheline.
"""

from __future__ import annotations

from .extract import ParsedDevice
from .tmsh_parser import strip_partition

COLUMNS = [
    "Device",
    "Hostname",
    "FlowType",
    "Source",
    "SourcePort",
    "Destination",
    "DestinationPort",
    "Protocol",
    "Action",
    "ObjectType",
    "ObjectName",
    "Detail",
    "NeedsReview",
]

DATAGROUP_COLUMNS = [
    "Device",
    "DataGroupName",
    "Type",
    "RecordKey",
    "RecordValue",
    "ReferencedByIRules",
]


def _join(values: list[str], empty: str = "any") -> str:
    return ", ".join(v for v in values if v) or empty


def _base_row(device: ParsedDevice, flow_type: str) -> dict:
    return {
        "Device": device.device_label,
        "Hostname": device.hostname or "",
        "FlowType": flow_type,
        "NeedsReview": "",
    }


def _datagroups_for_irules(device: ParsedDevice, irule_names: list[str]) -> list[str]:
    bare_irules = {strip_partition(r) for r in irule_names}
    if not bare_irules:
        return []
    return [
        strip_partition(dg.name)
        for dg in device.data_groups.values()
        if bare_irules & set(dg.referenced_by_irules)
    ]


def _ingress_rows(device: ParsedDevice) -> list[dict]:
    rows = []
    for vs in device.virtuals.values():
        vlans_detail = (
            "toutes (vlans-disabled)"
            if vs.vlans_disabled
            else (", ".join(vs.vlans) if vs.vlans else "non précisé")
        )
        pool_note = vs.pool or ("forwarding (pas de pool)" if vs.is_forwarding else "aucun pool (iRule ?)")
        review_reasons = []
        if not vs.enabled:
            review_reasons.append("VS désactivé (disabled)")
        if (vs.destination_address and "non résolu" in vs.destination_address) or (
            vs.source and "non résolu" in vs.source
        ):
            review_reasons.append(
                "adresse définie via une address-list (traffic-matching-criteria) absente de ce fichier"
            )
        detail = f"pool={pool_note}; vlans={vlans_detail}; profiles={', '.join(vs.profiles) or 'aucun'}"
        if vs.irules:
            bare_irules = [strip_partition(r) for r in vs.irules]
            detail += f"; iRules={', '.join(bare_irules)}"
            review_reasons.append("piloté par iRule(s) : le flux réel peut différer selon la logique TCL")
            dg_refs = _datagroups_for_irules(device, vs.irules)
            if dg_refs:
                detail += f"; data-groups référencés par ces iRules={', '.join(dg_refs)} (voir feuille DataGroups)"
        row = _base_row(device, "Ingress-LB")
        row.update(
            {
                "Source": vs.source or "0.0.0.0/0",
                "SourcePort": "any",
                "Destination": vs.destination_address or "?",
                "DestinationPort": vs.destination_port or "any (0)",
                "Protocol": vs.ip_protocol or "any",
                "Action": "Accept (LB)" if vs.enabled else "Accept (LB) - VS désactivé",
                "ObjectType": "Virtual Server",
                "ObjectName": vs.name,
                "Detail": detail,
                "NeedsReview": "; ".join(review_reasons),
            }
        )
        rows.append(row)
    return rows


def _resolve_snat_source(device: ParsedDevice, vs) -> tuple[str, str]:
    """Retourne (source_ip_affichee, detail_snat)."""
    if vs.snat_type == "automap":
        return "Self-IP F5 (automap)", "snat=automap"
    if vs.snat_type == "snat" and vs.snat_pool:
        snatpool = device.snatpools.get(vs.snat_pool)
        if snatpool and snatpool.addresses:
            return _join(snatpool.addresses, empty="?"), f"snat=snatpool:{strip_partition(vs.snat_pool)}"
        return f"snatpool introuvable ({vs.snat_pool})", "snat=snatpool (non résolu)"
    if vs.snat_type == "none":
        return vs.source or "IP client d'origine", "snat=none (IP client préservée)"
    # source-address-translation absent du virtual : comportement par défaut F5 = pas de SNAT
    return vs.source or "IP client d'origine", "snat=absent (défaut: pas de SNAT)"


def _backend_rows(device: ParsedDevice) -> list[dict]:
    rows = []
    for vs in device.virtuals.values():
        if not vs.pool:
            continue
        pool = device.pools.get(vs.pool)
        if not pool:
            row = _base_row(device, "Backend-LB")
            row.update(
                {
                    "Source": "?",
                    "SourcePort": "",
                    "Destination": f"pool introuvable ({vs.pool})",
                    "DestinationPort": "",
                    "Protocol": vs.ip_protocol or "any",
                    "Action": "LB",
                    "ObjectType": "Pool",
                    "ObjectName": vs.pool,
                    "Detail": f"virtual={vs.name}; pool référencé mais absent du fichier de config",
                    "NeedsReview": "pool introuvable dans ce fichier",
                }
            )
            rows.append(row)
            continue
        source_ip, snat_detail = _resolve_snat_source(device, vs)
        for member in pool.members:
            detail = f"virtual={vs.name}; {snat_detail}; monitor={pool.monitor or 'aucun'}"
            review = ""
            if member.is_fqdn:
                detail += "; membre résolu par FQDN (IP réelle dépendante du DNS au moment de la résolution)"
                review = "membre FQDN : IP réelle non figée dans la config"
            row = _base_row(device, "Backend-LB")
            row.update(
                {
                    "Source": source_ip,
                    "SourcePort": "any",
                    "Destination": member.address,
                    "DestinationPort": member.port or vs.destination_port or "any",
                    "Protocol": vs.ip_protocol or "any",
                    "Action": "LB",
                    "ObjectType": "Pool Member",
                    "ObjectName": f"{strip_partition(vs.pool)} -> {strip_partition(member.name)}",
                    "Detail": detail,
                    "NeedsReview": review,
                }
            )
            rows.append(row)
    return rows


def _firewall_rows(device: ParsedDevice) -> list[dict]:
    rows = []
    for rule in device.firewall_rules:
        detail = f"log={'oui' if rule.log else 'non'}"
        if rule.ref_rule_list:
            detail += f"; référence rule-list={rule.ref_rule_list}"
        row = _base_row(device, "Firewall-Rule")
        row.update(
            {
                "Source": _join(rule.src_addresses),
                "SourcePort": _join(rule.src_ports),
                "Destination": _join(rule.dst_addresses),
                "DestinationPort": _join(rule.dst_ports),
                "Protocol": rule.protocol or "any",
                "Action": rule.action or "n/a",
                "ObjectType": f"Firewall {rule.container_type}",
                "ObjectName": f"{strip_partition(rule.container_name)}/{rule.name}",
                "Detail": detail,
            }
        )
        rows.append(row)
    return rows


def _resolve_gtm_vs(device: ParsedDevice, server_ref: str, vs_ref: str) -> tuple[str, str]:
    server = device.gtm_servers.get(server_ref)
    if not server:
        return f"(server GTM introuvable: {server_ref})", ""
    entry = server.virtual_servers.get(vs_ref)
    if entry is None:
        for name, value in server.virtual_servers.items():
            if strip_partition(name) == strip_partition(vs_ref):
                entry = value
                break
    if entry is None:
        return f"(virtual-server GTM introuvable: {vs_ref})", ""
    addr, port = entry
    return addr or "?", port or ""


def _gtm_rows(device: ParsedDevice) -> list[dict]:
    rows = []
    for wideip in device.gtm_wideips:
        if not wideip.pools:
            continue
        for pool_name in wideip.pools:
            pool = device.gtm_pools.get(pool_name)
            if not pool:
                row = _base_row(device, "GTM-DNS")
                row.update(
                    {
                        "Source": "Internet / clients DNS",
                        "SourcePort": "any",
                        "Destination": f"pool GTM introuvable ({pool_name})",
                        "DestinationPort": "",
                        "Protocol": wideip.record_type or "?",
                        "Action": "GTM LB",
                        "ObjectType": "GTM WideIP",
                        "ObjectName": wideip.name,
                        "Detail": "",
                    }
                )
                rows.append(row)
                continue
            for member in pool.members:
                addr, port = _resolve_gtm_vs(device, member.server_ref, member.vs_ref)
                row = _base_row(device, "GTM-DNS")
                row.update(
                    {
                        "Source": "Internet / clients DNS",
                        "SourcePort": "any",
                        "Destination": addr,
                        "DestinationPort": port,
                        "Protocol": wideip.record_type or "?",
                        "Action": f"GTM LB ({pool.lb_mode or '?'})",
                        "ObjectType": "GTM WideIP",
                        "ObjectName": f"{wideip.name} -> {strip_partition(pool_name)} -> {strip_partition(member.server_ref)}:{strip_partition(member.vs_ref)}",
                        "Detail": f"datacenter/server={strip_partition(member.server_ref)}",
                    }
                )
                rows.append(row)
    return rows


def _strip_route_domain(addr: str) -> str:
    """10.1.1.10%2 -> 10.1.1.10 (retire le route domain F5 pour comparaison)."""
    return addr.split("%", 1)[0] if addr else addr


def _orphan_vip_rows(device: ParsedDevice) -> list[dict]:
    """VIP (ltm virtual-address) déclarées mais non pointées par un ltm virtual.

    Signale les floating-IP potentiellement orphelines (VS supprimé sans
    nettoyage, ou service rendu par un autre mécanisme que LTM) : un point
    d'attention pour la cartographie, pas une erreur de parsing.
    """
    used_addresses = {
        _strip_route_domain(vs.destination_address)
        for vs in device.virtuals.values()
        if vs.destination_address
    }
    rows = []
    for va in device.virtual_addresses.values():
        if _strip_route_domain(va.address) in used_addresses:
            continue
        row = _base_row(device, "VIP-Orphan")
        row.update(
            {
                "Source": "?",
                "SourcePort": "",
                "Destination": va.address,
                "DestinationPort": "",
                "Protocol": "?",
                "Action": "n/a" if va.enabled else "n/a (désactivée)",
                "ObjectType": "Virtual Address",
                "ObjectName": va.name,
                "Detail": (
                    (f"{va.description}; " if va.description else "")
                    + "adresse déclarée (ltm virtual-address) mais non utilisée comme "
                    "destination d'un ltm virtual dans ce fichier : VS supprimé, IP "
                    "réservée, ou service géré ailleurs (routage direct, autre module)."
                ),
                "NeedsReview": "VIP orpheline - à vérifier manuellement",
            }
        )
        rows.append(row)
    return rows


def build_flow_matrix(devices: list[ParsedDevice]) -> list[dict]:
    """Construit la matrice de flux consolidée pour un ou plusieurs devices F5."""
    rows: list[dict] = []
    for device in devices:
        rows.extend(_ingress_rows(device))
        rows.extend(_backend_rows(device))
        rows.extend(_firewall_rows(device))
        rows.extend(_gtm_rows(device))
        rows.extend(_orphan_vip_rows(device))
    return rows


def build_datagroup_rows(devices: list[ParsedDevice]) -> list[dict]:
    """Extrait les data-groups (tables de correspondance utilisées par les iRules)
    en table de référence, pour permettre une revue manuelle du routage caché
    que l'on ne cherche pas à interpréter automatiquement (logique TCL)."""
    rows = []
    for device in devices:
        for dg in device.data_groups.values():
            refs = ", ".join(dg.referenced_by_irules) or "aucune iRule identifiée"
            if not dg.records:
                rows.append(
                    {
                        "Device": device.device_label,
                        "DataGroupName": strip_partition(dg.name),
                        "Type": dg.type or "",
                        "RecordKey": "",
                        "RecordValue": "",
                        "ReferencedByIRules": refs,
                    }
                )
                continue
            for key, value in dg.records.items():
                rows.append(
                    {
                        "Device": device.device_label,
                        "DataGroupName": strip_partition(dg.name),
                        "Type": dg.type or "",
                        "RecordKey": key,
                        "RecordValue": value or "",
                        "ReferencedByIRules": refs,
                    }
                )
    return rows
