"""
cmdb.py — Fetch assets from ServiceNow CMDB or a local CSV fallback.

Returns a list of dicts:
  {
    "hostname":   "SERVER01",
    "ip_address": "10.0.0.1",
    "os_name":    "Windows Server 2019",
    "os_key":     "Win-2019-MS",       # matched from config.OS_KEYWORD_MAP
    "scan_name":  "Agent-Win-2019-MS-IM-Compliance",
    "group_name": "Ingram Micro-Win-2019-MS",
  }
"""

import os
import requests
import pandas as pd
from config import (
    SNOW_BASE, SNOW_USER, SNOW_PASS, SNOW_CMDB_TABLE,
    CMDB_CSV_PATH, OS_KEYWORD_MAP, CIS_SCANS
)
from utils import log


# ── OS matching ───────────────────────────────────────────────────────────────

def match_os(os_string: str) -> str | None:
    """Match a raw OS string from CMDB to a CIS_SCANS key."""
    if not os_string:
        return None
    lower = os_string.lower().strip()
    for keyword, key in OS_KEYWORD_MAP.items():
        if keyword in lower:
            return key
    return None


def enrich(asset: dict) -> dict | None:
    """Add os_key, scan_name, group_name. Return None if OS not supported."""
    os_key = match_os(asset.get("os_name", ""))
    if not os_key:
        log(f"  ⚠ No CIS scan mapped for OS: {asset.get('os_name')} ({asset.get('hostname')}) — skipping")
        return None
    scan_cfg = CIS_SCANS[os_key]
    return {
        **asset,
        "os_key":     os_key,
        "scan_name":  scan_cfg["scan_name"],
        "group_name": scan_cfg["group_name"],
        "os_family":  scan_cfg["os_family"],
    }


# ── ServiceNow source ─────────────────────────────────────────────────────────

def fetch_from_servicenow() -> list[dict]:
    """
    Pull all active servers from ServiceNow CMDB table.
    Filters: operational_status=1 (operational), install_status=1 (installed)
    """
    log("Fetching assets from ServiceNow CMDB …")
    assets = []
    offset = 0
    limit  = 1000

    while True:
        url = (
            f"{SNOW_BASE}/table/{SNOW_CMDB_TABLE}"
            f"?sysparm_query=operational_status%3D1%5Einstall_status%3D1"
            f"&sysparm_fields=name,ip_address,os,os_version,sys_id"
            f"&sysparm_limit={limit}&sysparm_offset={offset}"
        )
        r = requests.get(url, auth=(SNOW_USER, SNOW_PASS), timeout=60)
        r.raise_for_status()
        records = r.json().get("result", [])
        if not records:
            break

        for rec in records:
            # Combine OS name + version for better matching
            os_str = f"{rec.get('os', '')} {rec.get('os_version', '')}".strip()
            assets.append({
                "hostname":   rec.get("name", ""),
                "ip_address": rec.get("ip_address", ""),
                "os_name":    os_str,
                "sys_id":     rec.get("sys_id", ""),
            })

        log(f"  Fetched {offset + len(records)} records so far …")
        if len(records) < limit:
            break
        offset += limit

    log(f"ServiceNow: {len(assets)} total assets fetched")
    return assets


# ── CSV fallback source ───────────────────────────────────────────────────────

def fetch_from_csv() -> list[dict]:
    """
    Load assets from input/cmdb_assets.csv.
    Required columns: hostname, ip_address, os_name
    """
    if not os.path.exists(CMDB_CSV_PATH):
        raise FileNotFoundError(
            f"CMDB CSV not found: {CMDB_CSV_PATH}\n"
            "Create input/cmdb_assets.csv with columns: hostname, ip_address, os_name"
        )
    df = pd.read_csv(CMDB_CSV_PATH)
    df.columns = df.columns.str.strip().str.lower()
    required = {"hostname", "ip_address", "os_name"}
    missing  = required - set(df.columns)
    if missing:
        raise ValueError(f"cmdb_assets.csv missing columns: {missing}")

    df = df.fillna("").astype(str)
    log(f"CSV CMDB: loaded {len(df)} assets from {CMDB_CSV_PATH}")
    return df.to_dict("records")


# ── Main entry ────────────────────────────────────────────────────────────────

def get_assets() -> list[dict]:
    """
    Fetch assets from ServiceNow if credentials are set, otherwise fall back to CSV.
    Returns only assets whose OS maps to a supported CIS scan.
    """
    use_snow = bool(SNOW_INSTANCE and SNOW_USER and SNOW_PASS)

    raw = fetch_from_servicenow() if use_snow else fetch_from_csv()

    enriched = []
    skipped  = 0
    for asset in raw:
        result = enrich(asset)
        if result:
            enriched.append(result)
        else:
            skipped += 1

    log(f"Assets matched to CIS scans: {len(enriched)} | Skipped (unsupported OS): {skipped}")
    return enriched


# Expose for import
SNOW_INSTANCE = os.environ.get("SNOW_INSTANCE", "")
