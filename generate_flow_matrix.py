#!/usr/bin/env python3
"""CLI : génère une matrice de flux réseau à partir de fichiers de config F5 BIG-IP.

Usage :
    python generate_flow_matrix.py --input bigip1.conf bigip2.conf --output-dir out
    python generate_flow_matrix.py --input ./configs/ --device-labels DC1 DC2

Chaque fichier d'entrée doit être un export bigip.conf ou un SCF (Single
Configuration File) au format tmsh natif. Un dossier peut aussi être passé :
tous les fichiers *.conf/*.scf qu'il contient (non récursif) seront traités.

Sortie : matrice_de_flux.csv et matrice_de_flux.xlsx dans --output-dir,
consolidant tous les fichiers d'entrée avec une colonne Device/Hostname
pour identifier l'origine de chaque ligne.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from f5_flow_matrix.export import write_csv, write_xlsx
from f5_flow_matrix.extract import parse_device
from f5_flow_matrix.flow_matrix import DATAGROUP_COLUMNS, build_datagroup_rows, build_flow_matrix


def _collect_input_files(inputs: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in inputs:
        p = Path(raw)
        if p.is_dir():
            found = sorted(list(p.glob("*.conf")) + list(p.glob("*.scf")))
            if not found:
                print(f"[!] Aucun fichier .conf/.scf trouvé dans le dossier {p}", file=sys.stderr)
            files.extend(found)
        elif p.is_file():
            files.append(p)
        else:
            print(f"[!] Fichier ou dossier introuvable : {p}", file=sys.stderr)
    return files


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Génère une matrice de flux réseau à partir de fichiers bigip.conf/SCF F5 BIG-IP."
    )
    parser.add_argument(
        "--input", "-i", nargs="+", required=True,
        help="Un ou plusieurs fichiers bigip.conf/SCF, et/ou dossiers les contenant.",
    )
    parser.add_argument(
        "--device-labels", nargs="*", default=None,
        help="Labels à associer à chaque fichier d'entrée, dans le même ordre "
             "(ex: nom de datacenter). Par défaut, le nom de fichier est utilisé.",
    )
    parser.add_argument(
        "--output-dir", "-o", default="output",
        help="Dossier de sortie pour la matrice générée (défaut: ./output).",
    )
    parser.add_argument(
        "--basename", default="matrice_de_flux",
        help="Nom de base des fichiers générés (défaut: matrice_de_flux).",
    )
    parser.add_argument(
        "--format", choices=["csv", "xlsx", "both"], default="both",
        help="Format(s) de sortie à générer (défaut: both).",
    )
    args = parser.parse_args()

    files = _collect_input_files(args.input)
    if not files:
        print("[x] Aucun fichier de configuration à traiter.", file=sys.stderr)
        return 1

    if args.device_labels and len(args.device_labels) != len(files):
        print(
            f"[x] --device-labels ({len(args.device_labels)}) doit correspondre "
            f"au nombre de fichiers traités ({len(files)}) : {[str(f) for f in files]}",
            file=sys.stderr,
        )
        return 1

    devices = []
    for i, f in enumerate(files):
        label = args.device_labels[i] if args.device_labels else f.stem
        text = f.read_text(encoding="utf-8", errors="replace")
        try:
            device = parse_device(text, device_label=label)
        except ValueError as e:
            print(f"[x] Erreur de parsing sur {f} : {e}", file=sys.stderr)
            return 1
        devices.append(device)
        print(
            f"[+] {f.name} -> device='{label}' hostname='{device.hostname or '?'}' : "
            f"{len(device.virtuals)} virtual servers, {len(device.pools)} pools, "
            f"{len(device.virtual_addresses)} virtual-address, {len(device.nodes)} nodes, "
            f"{len(device.firewall_rules)} règles firewall, {len(device.gtm_wideips)} wideips GTM, "
            f"{len(device.data_groups)} data-groups"
        )

    rows = build_flow_matrix(devices)
    dg_rows = build_datagroup_rows(devices)
    review_count = sum(1 for r in rows if r.get("NeedsReview"))
    print(f"[+] {len(rows)} lignes de flux générées au total ({review_count} à vérifier manuellement).")

    out_dir = Path(args.output_dir)
    if args.format in ("csv", "both"):
        csv_path = out_dir / f"{args.basename}.csv"
        write_csv(rows, csv_path)
        print(f"[+] CSV écrit : {csv_path}")
        if dg_rows:
            dg_csv_path = out_dir / f"{args.basename}_datagroups.csv"
            write_csv(dg_rows, dg_csv_path, columns=DATAGROUP_COLUMNS)
            print(f"[+] CSV data-groups (référence iRules) écrit : {dg_csv_path}")
    if args.format in ("xlsx", "both"):
        xlsx_path = out_dir / f"{args.basename}.xlsx"
        write_xlsx(rows, xlsx_path, datagroup_rows=dg_rows)
        print(f"[+] XLSX écrit ({3 if dg_rows else 2} feuilles) : {xlsx_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
