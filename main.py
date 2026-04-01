"""
main.py — CIS Benchmark Automation Orchestrator

Modes (set MODE env var):
  full          (default) — CMDB sync → launch scans → poll → export → report
  sync_only     — sync CMDB assets to Tenable agent groups only
  scan_only     — launch scans and poll (skip CMDB sync)
  report_only   — export results from already-completed scans and report
"""

import os
import json
from datetime import datetime
from config import OUTPUT_DIR, CIS_SCANS
from utils import log
from cmdb import get_assets
from tenable import (
    sync_assets_to_groups,
    launch_all_cis_scans,
    poll_all_scans,
    export_and_process_all,
)
from report import generate_report

MODE = os.getenv("MODE", "full").lower()
VALID_MODES = {"full", "sync_only", "scan_only", "report_only"}


def main() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")

    log("=" * 65)
    log("CIS BENCHMARK COMPLIANCE AUTOMATION")
    log(f"Mode:   {MODE}")
    log(f"Output: {OUTPUT_DIR}")
    log("=" * 65)

    if MODE not in VALID_MODES:
        raise ValueError(f"Invalid MODE={MODE!r}. Choose from: {VALID_MODES}")

    scan_results = []
    all_rows     = []

    # ── Step 1: Sync CMDB → Tenable agent groups ──────────────────────────────
    if MODE in ("full", "sync_only"):
        log("\n── STEP 1: CMDB → Tenable Agent Group Sync ──")
        assets = get_assets()
        assets = sync_assets_to_groups(assets)

        # Save asset map for reference
        asset_path = os.path.join(OUTPUT_DIR, f"assets_{date_str}.json")
        with open(asset_path, "w") as f:
            json.dump(assets, f, indent=2)
        log(f"Asset map saved → {asset_path}")

        if MODE == "sync_only":
            log("sync_only mode — done.")
            return

    # ── Step 2: Launch all CIS scans ─────────────────────────────────────────
    if MODE in ("full", "scan_only"):
        log("\n── STEP 2: Launch CIS Scans ──")
        scan_results = launch_all_cis_scans()

        # Save intermediate state
        state_path = os.path.join(OUTPUT_DIR, f"scan_state_{date_str}.json")
        with open(state_path, "w") as f:
            json.dump(scan_results, f, indent=2)
        log(f"Scan state saved → {state_path}")

        # ── Step 3: Poll until all complete ──────────────────────────────────
        log("\n── STEP 3: Polling Scan Completion ──")
        scan_results = poll_all_scans(scan_results)

        # Update state file
        with open(state_path, "w") as f:
            json.dump(scan_results, f, indent=2)

    # ── Step 4: Export CSVs + process results ─────────────────────────────────
    log("\n── STEP 4: Export & Process Results ──")

    # For report_only — load previously saved scan state
    if MODE == "report_only":
        # Find most recent scan_state file
        state_files = sorted([
            f for f in os.listdir(OUTPUT_DIR) if f.startswith("scan_state_")
        ])
        if state_files:
            state_path = os.path.join(OUTPUT_DIR, state_files[-1])
            with open(state_path) as f:
                scan_results = json.load(f)
            log(f"Loaded scan state from {state_path}")
        else:
            log("⚠ No scan state file found — using all CIS scans as reference")
            # Build minimal scan_results from config for export
            from tenable import get_all_scans, find_scan_by_name
            all_scans = get_all_scans()
            for os_key, cfg in CIS_SCANS.items():
                scan = find_scan_by_name(cfg["scan_name"], all_scans)
                scan_results.append({
                    "os_key":    os_key,
                    "scan_name": cfg["scan_name"],
                    "scan_id":   str(scan["id"]) if scan else "",
                    "status":    "COMPLETED" if scan else "NOT_FOUND",
                    "os_family": cfg["os_family"],
                })

    raw_output = os.path.join(OUTPUT_DIR, "raw_exports")
    all_rows   = export_and_process_all(scan_results, raw_output)

    # ── Step 5: Generate report ───────────────────────────────────────────────
    log("\n── STEP 5: Generate Compliance Report ──")
    generate_report(all_rows, scan_results, OUTPUT_DIR)

    log("\n✅ CIS Benchmark Automation Complete")


if __name__ == "__main__":
    main()
