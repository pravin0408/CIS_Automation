"""
tenable.py — Tenable.io API operations for CIS benchmark automation.

Covers:
  - Agent group lookup / assignment
  - Scan lookup and launch
  - Scan status polling
  - CSV export download
  - Results processing (Compliant / Non-Compliant / Manual Verification)
"""

import time
import os
import io
import csv
import zipfile
from config import CIS_SCANS, POLL_INTERVAL, MAX_POLL_WAIT
from utils import log, tenable_request


# ═══════════════════════════════════════════════════════════════════════════════
# Agent groups
# ═══════════════════════════════════════════════════════════════════════════════

def get_all_agent_groups() -> dict[str, str]:
    """Return {group_name: group_id} for all agent groups."""
    r = tenable_request("GET", "/scanners/1/agent-groups")
    groups = r.get("groups", [])
    return {g["name"]: str(g["id"]) for g in groups}


def get_agent_by_hostname(hostname: str) -> dict | None:
    """Find a linked Tenable agent by hostname."""
    r = tenable_request("GET", f"/scanners/1/agents?f=hostname:match:{hostname}&limit=1")
    agents = r.get("agents", [])
    return agents[0] if agents else None


def assign_agent_to_group(agent_id: str, group_id: str, hostname: str) -> bool:
    """Add agent to the specified group. Returns True on success."""
    try:
        tenable_request(
            "PUT",
            f"/scanners/1/agent-groups/{group_id}/agents/{agent_id}"
        )
        log(f"  ✓ Agent {hostname} assigned to group {group_id}")
        return True
    except Exception as e:
        log(f"  ✗ Failed to assign {hostname}: {e}")
        return False


def sync_assets_to_groups(assets: list[dict]) -> list[dict]:
    """
    For each asset from CMDB, find its Tenable agent and ensure it
    is in the correct agent group for its OS.
    Returns enriched assets list with agent_id added.
    """
    log("Syncing CMDB assets to Tenable agent groups …")
    all_groups = get_all_agent_groups()
    results    = []

    for asset in assets:
        hostname   = asset["hostname"]
        group_name = asset["group_name"]
        group_id   = all_groups.get(group_name)

        if not group_id:
            log(f"  ⚠ Group not found in Tenable: '{group_name}' for {hostname}")
            asset["agent_id"]    = ""
            asset["group_synced"] = False
            results.append(asset)
            continue

        agent = get_agent_by_hostname(hostname)
        if not agent:
            log(f"  ⚠ No Tenable agent found for hostname: {hostname}")
            asset["agent_id"]    = ""
            asset["group_synced"] = False
            results.append(asset)
            continue

        agent_id = str(agent["id"])
        synced   = assign_agent_to_group(agent_id, group_id, hostname)
        asset["agent_id"]    = agent_id
        asset["group_synced"] = synced
        results.append(asset)

    synced_count = sum(1 for a in results if a.get("group_synced"))
    log(f"Group sync complete — {synced_count}/{len(results)} agents assigned")
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# Scans
# ═══════════════════════════════════════════════════════════════════════════════

def get_all_scans() -> list[dict]:
    """Return all scans from Tenable."""
    r = tenable_request("GET", "/scans")
    return r.get("scans", []) or []


def find_scan_by_name(scan_name: str, all_scans: list[dict]) -> dict | None:
    """Find a scan by exact name match."""
    for s in all_scans:
        if s.get("name", "").strip() == scan_name.strip():
            return s
    return None


def launch_scan(scan_id: str, scan_name: str) -> str | None:
    """Launch a scan. Returns scan_uuid or None on failure."""
    try:
        r = tenable_request("POST", f"/scans/{scan_id}/launch")
        uuid = r.get("scan_uuid", "")
        log(f"  ✓ Launched: {scan_name} → uuid={uuid}")
        return uuid
    except Exception as e:
        log(f"  ✗ Failed to launch {scan_name}: {e}")
        return None


def get_scan_status(scan_id: str) -> str:
    """Get current status of a scan."""
    r = tenable_request("GET", f"/scans/{scan_id}")
    info = r.get("info", {})
    return info.get("status", "unknown")


def wait_for_scan(scan_id: str, scan_name: str) -> str:
    """Poll until scan reaches a terminal state. Returns final status."""
    terminal = {"completed", "canceled", "aborted", "empty"}
    elapsed  = 0

    while True:
        status = get_scan_status(scan_id)
        log(f"  ↻ {scan_name} — {elapsed}s — {status}")

        if status.lower() in terminal:
            return status

        if elapsed >= MAX_POLL_WAIT:
            log(f"  ⏱ Timeout after {MAX_POLL_WAIT}s — {scan_name}")
            return "timeout"

        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL


def launch_all_cis_scans() -> list[dict]:
    """
    Find and launch all 14 CIS scans defined in config.
    Returns list of scan result dicts with scan_id, name, status.
    """
    log("Fetching scan list from Tenable …")
    all_scans = get_all_scans()
    results   = []

    for os_key, cfg in CIS_SCANS.items():
        scan_name = cfg["scan_name"]
        scan      = find_scan_by_name(scan_name, all_scans)

        if not scan:
            log(f"  ⚠ Scan not found in Tenable: '{scan_name}'")
            results.append({
                "os_key":    os_key,
                "scan_name": scan_name,
                "scan_id":   "",
                "status":    "NOT_FOUND",
                "os_family": cfg["os_family"],
            })
            continue

        scan_id = str(scan["id"])
        uuid    = launch_scan(scan_id, scan_name)
        results.append({
            "os_key":    os_key,
            "scan_name": scan_name,
            "scan_id":   scan_id,
            "scan_uuid": uuid or "",
            "status":    "LAUNCHED" if uuid else "LAUNCH_FAILED",
            "os_family": cfg["os_family"],
        })

    return results


def poll_all_scans(scan_results: list[dict]) -> list[dict]:
    """
    Wait for all launched scans to complete (in sequence — Tenable
    rate-limits concurrent status polls).
    Updates status in-place and returns updated list.
    """
    log("Polling scans for completion …")
    for r in scan_results:
        if r["status"] not in ("LAUNCHED",):
            continue
        final = wait_for_scan(r["scan_id"], r["scan_name"])
        r["status"] = final.upper()
    return scan_results


# ═══════════════════════════════════════════════════════════════════════════════
# Export & process results
# ═══════════════════════════════════════════════════════════════════════════════

def export_scan_csv(scan_id: str, scan_name: str) -> bytes | None:
    """
    Request a CSV export for a completed scan.
    Returns raw CSV bytes or None on failure.
    """
    try:
        # Request export
        r = tenable_request(
            "POST",
            f"/scans/{scan_id}/export",
            json={"format": "csv", "chapters": "vuln_hosts_summary;vuln_by_host"}
        )
        file_id = r.get("file")
        if not file_id:
            log(f"  ⚠ No file_id returned for export of {scan_name}")
            return None

        # Poll export status
        for _ in range(30):
            status_r = tenable_request("GET", f"/scans/{scan_id}/export/{file_id}/status")
            if status_r.get("status") == "ready":
                break
            time.sleep(10)
        else:
            log(f"  ⚠ Export timed out for {scan_name}")
            return None

        # Download
        import requests as _req
        from config import TENABLE_BASE, TENABLE_HEADERS
        dl = _req.get(
            f"{TENABLE_BASE}/scans/{scan_id}/export/{file_id}/download",
            headers=TENABLE_HEADERS,
            timeout=120
        )
        dl.raise_for_status()
        log(f"  ✓ Exported {scan_name} — {len(dl.content)} bytes")
        return dl.content

    except Exception as e:
        log(f"  ✗ Export failed for {scan_name}: {e}")
        return None


def process_csv(raw_csv: bytes, scan_name: str, os_key: str) -> list[dict]:
    """
    Process a Tenable CSV export using the same logic as the Power Query
    in the document:
      - Keep only compliance check rows
      - Map Risk → Compliant / Non-Compliant / Manual Verification
      - Extract Plugin name from Description field
    """
    rows = []
    try:
        text   = raw_csv.decode("utf-8-sig", errors="replace")
        reader = csv.DictReader(io.StringIO(text))

        for row in reader:
            name = row.get("Name", "").strip()
            # Keep only compliance check rows (Windows or Unix)
            if name not in ("Windows Compliance Checks", "Unix Compliance Checks"):
                continue

            risk = row.get("Risk", "").strip()
            # Map exactly as Power Query does:
            if risk == "None":
                compliance = "Compliant"
            elif risk == "High":
                compliance = "Non-Compliant"
            elif risk == "Medium":
                compliance = "Manual Verification"
            else:
                compliance = risk or "Unknown"

            desc        = row.get("Description", "")
            plugin_name = desc.split(": [")[0].strip() if ": [" in desc else desc[:80]

            rows.append({
                "os_key":       os_key,
                "scan_name":    scan_name,
                "host":         row.get("Host", ""),
                "ip_address":   row.get("IP Address", ""),
                "fqdn":         row.get("FQDN", ""),
                "os":           row.get("OS", ""),
                "compliance":   compliance,
                "plugin_name":  plugin_name,
                "description":  desc[:200],
                "plugin_output": row.get("Plugin Output", "")[:300],
            })
    except Exception as e:
        log(f"  ✗ Failed to process CSV for {scan_name}: {e}")

    return rows


def export_and_process_all(scan_results: list[dict], output_dir: str) -> list[dict]:
    """
    For each completed scan: export CSV, process it, save raw CSV.
    Returns all processed compliance rows combined.
    """
    os.makedirs(output_dir, exist_ok=True)
    all_rows = []

    for s in scan_results:
        if s["status"].upper() not in ("COMPLETED",):
            log(f"  Skipping export for {s['scan_name']} — status: {s['status']}")
            continue

        raw = export_scan_csv(s["scan_id"], s["scan_name"])
        if not raw:
            continue

        # Save raw CSV
        safe_name = s["scan_name"].replace(" ", "_").replace("/", "-")
        raw_path  = os.path.join(output_dir, f"raw_{safe_name}.csv")
        with open(raw_path, "wb") as f:
            f.write(raw)

        rows = process_csv(raw, s["scan_name"], s["os_key"])
        log(f"  Processed {s['scan_name']}: {len(rows)} compliance rows")
        all_rows.extend(rows)

    return all_rows
