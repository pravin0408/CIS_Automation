"""
report.py — Generate CIS compliance report from processed Tenable results.

Outputs:
  output/cis_compliance_YYYY-MM-DD.html   — visual dashboard
  output/cis_compliance_YYYY-MM-DD.csv    — flat data
  output/cis_scan_summary_YYYY-MM-DD.csv  — one row per scan
"""

import os
import csv
import json
from datetime import datetime, timezone
from config import CIS_SCANS
from utils import log


# ── Compliance colour map ────────────────────────────────────────────────────
COMP_COLOR = {
    "Compliant":           ("#d1fae5", "#065f46"),
    "Non-Compliant":       ("#fee2e2", "#991b1b"),
    "Manual Verification": ("#fef3c7", "#92400e"),
    "Unknown":             ("#f3f4f6", "#374151"),
}

SCAN_STATUS_COLOR = {
    "COMPLETED":     ("#d1fae5", "#065f46"),
    "LAUNCHED":      ("#dbeafe", "#1e40af"),
    "LAUNCH_FAILED": ("#fee2e2", "#991b1b"),
    "NOT_FOUND":     ("#fef3c7", "#92400e"),
    "TIMEOUT":       ("#fef3c7", "#92400e"),
    "CANCELED":      ("#f3f4f6", "#374151"),
}


def _badge(text: str, color_map: dict) -> str:
    bg, fg = color_map.get(text, ("#f3f4f6", "#374151"))
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 10px;'
        f'border-radius:12px;font-size:12px;font-weight:600;white-space:nowrap">'
        f'{text}</span>'
    )


# ── Summarise rows ────────────────────────────────────────────────────────────

def summarise(rows: list[dict], scan_results: list[dict]) -> dict:
    total       = len(rows)
    compliant   = sum(1 for r in rows if r["compliance"] == "Compliant")
    non_comp    = sum(1 for r in rows if r["compliance"] == "Non-Compliant")
    manual      = sum(1 for r in rows if r["compliance"] == "Manual Verification")

    scans_ok    = sum(1 for s in scan_results if s["status"].upper() == "COMPLETED")
    scans_fail  = sum(1 for s in scan_results if s["status"].upper() in ("LAUNCH_FAILED", "NOT_FOUND", "TIMEOUT"))

    return {
        "generated_at":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "total_checks":  total,
        "compliant":     compliant,
        "non_compliant": non_comp,
        "manual":        manual,
        "scans_run":     len(scan_results),
        "scans_ok":      scans_ok,
        "scans_fail":    scans_fail,
        "compliance_pct": f"{compliant / total * 100:.1f}%" if total else "—",
    }


# ── Print to GitHub Actions log ───────────────────────────────────────────────

def print_summary(rows: list[dict], scan_results: list[dict], stats: dict) -> None:
    W = 90
    print(f"\n{'═' * W}")
    print(f"  CIS BENCHMARK COMPLIANCE REPORT — {stats['generated_at']}")
    print(f"{'═' * W}")
    print(f"  Scans run:        {stats['scans_ok']}/{stats['scans_run']} completed")
    print(f"  Total checks:     {stats['total_checks']}")
    print(f"  ✅ Compliant:     {stats['compliant']}")
    print(f"  ❌ Non-Compliant: {stats['non_compliant']}")
    print(f"  ⚠  Manual Review: {stats['manual']}")
    print(f"  Compliance rate:  {stats['compliance_pct']}")
    print(f"\n  {'SCAN':<50} STATUS")
    print(f"  {'─' * 70}")
    for s in scan_results:
        icon = "✅" if s["status"].upper() == "COMPLETED" else "❌"
        print(f"  {icon}  {s['scan_name']:<48} {s['status']}")
    print(f"{'═' * W}\n")


# ── Write CSV ─────────────────────────────────────────────────────────────────

def write_csv(rows: list[dict], path: str) -> None:
    if not rows:
        log(f"No rows to write to {path}")
        return
    fields = ["os_key", "scan_name", "host", "ip_address", "fqdn",
              "os", "compliance", "plugin_name", "description"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    log(f"CSV  → {path}")


def write_scan_summary_csv(scan_results: list[dict], path: str) -> None:
    fields = ["os_key", "scan_name", "os_family", "scan_id", "status"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(scan_results)
    log(f"Scan summary CSV → {path}")


# ── Write HTML ────────────────────────────────────────────────────────────────

def write_html(rows: list[dict], scan_results: list[dict], stats: dict, path: str) -> None:

    # Scan summary table
    scan_rows_html = ""
    for s in scan_results:
        scan_rows_html += f"""
        <tr>
          <td>{s['os_key']}</td>
          <td>{s['scan_name']}</td>
          <td style="text-align:center">{_badge(s['status'].upper(), SCAN_STATUS_COLOR)}</td>
        </tr>"""

    # Compliance breakdown per OS
    by_os: dict[str, dict] = {}
    for r in rows:
        key = r["os_key"]
        if key not in by_os:
            by_os[key] = {"Compliant": 0, "Non-Compliant": 0, "Manual Verification": 0}
        by_os[key][r["compliance"]] = by_os[key].get(r["compliance"], 0) + 1

    os_rows_html = ""
    for os_key, counts in sorted(by_os.items()):
        total_os = sum(counts.values())
        pct = f"{counts['Compliant'] / total_os * 100:.0f}%" if total_os else "—"
        os_rows_html += f"""
        <tr>
          <td><strong>{os_key}</strong></td>
          <td style="color:#059669;text-align:center">{counts['Compliant']}</td>
          <td style="color:#dc2626;text-align:center">{counts['Non-Compliant']}</td>
          <td style="color:#d97706;text-align:center">{counts['Manual Verification']}</td>
          <td style="text-align:center"><strong>{pct}</strong></td>
        </tr>"""

    # Detail rows (Non-Compliant first)
    priority = {"Non-Compliant": 0, "Manual Verification": 1, "Compliant": 2}
    sorted_rows = sorted(rows, key=lambda r: (priority.get(r["compliance"], 3), r["os_key"], r["host"]))

    detail_html = ""
    for i, r in enumerate(sorted_rows[:500], 1):   # cap at 500 rows for page perf
        detail_html += f"""
        <tr>
          <td style="font-size:11px;color:#94a3b8">{i}</td>
          <td><strong>{r['host']}</strong></td>
          <td style="font-size:11px">{r['ip_address']}</td>
          <td style="font-size:11px">{r['os_key']}</td>
          <td>{_badge(r['compliance'], COMP_COLOR)}</td>
          <td style="font-size:11px">{r['plugin_name'][:80]}</td>
        </tr>"""

    if len(rows) > 500:
        detail_html += f"""
        <tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:16px">
          … {len(rows) - 500} more rows in the CSV export
        </td></tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CIS Compliance Report — {stats['generated_at']}</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         background:#f8fafc; color:#1e293b; padding:32px }}
  h1   {{ font-size:22px; font-weight:700; margin-bottom:4px }}
  h2   {{ font-size:16px; font-weight:600; margin:32px 0 12px }}
  .sub {{ font-size:13px; color:#64748b; margin-bottom:28px }}
  .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:32px }}
  .card  {{ background:#fff; border:1px solid #e2e8f0; border-radius:12px;
            padding:18px 24px; min-width:120px; flex:1; text-align:center }}
  .card .num {{ font-size:34px; font-weight:700 }}
  .card .lbl {{ font-size:11px; color:#64748b; margin-top:4px;
                text-transform:uppercase; letter-spacing:.05em }}
  .green .num {{ color:#059669 }} .red .num {{ color:#dc2626 }}
  .amber .num {{ color:#d97706 }} .blue  .num {{ color:#2563eb }}
  .tbl-wrap {{ background:#fff; border:1px solid #e2e8f0;
               border-radius:12px; overflow:hidden; margin-bottom:32px }}
  table  {{ width:100%; border-collapse:collapse; font-size:13px }}
  thead  {{ background:#f1f5f9 }}
  th     {{ padding:10px 14px; text-align:left; font-weight:600; font-size:11px;
            color:#475569; white-space:nowrap; text-transform:uppercase }}
  td     {{ padding:10px 14px; border-top:1px solid #f1f5f9; vertical-align:middle }}
  tr:hover td {{ background:#f8fafc }}
  .footer {{ margin-top:24px; font-size:12px; color:#94a3b8; text-align:center }}
</style>
</head>
<body>
  <h1>🛡 CIS Benchmark Compliance Report</h1>
  <p class="sub">
    Generated {stats['generated_at']} &nbsp;·&nbsp;
    {stats['scans_ok']}/{stats['scans_run']} scans completed &nbsp;·&nbsp;
    Compliance rate: <strong>{stats['compliance_pct']}</strong>
  </p>

  <div class="cards">
    <div class="card green">
      <div class="num">{stats['compliant']}</div>
      <div class="lbl">Compliant</div>
    </div>
    <div class="card red">
      <div class="num">{stats['non_compliant']}</div>
      <div class="lbl">Non-Compliant</div>
    </div>
    <div class="card amber">
      <div class="num">{stats['manual']}</div>
      <div class="lbl">Manual Review</div>
    </div>
    <div class="card blue">
      <div class="num">{stats['total_checks']}</div>
      <div class="lbl">Total Checks</div>
    </div>
    <div class="card">
      <div class="num">{stats['scans_ok']}</div>
      <div class="lbl">Scans OK</div>
    </div>
  </div>

  <h2>Scan Status</h2>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>OS</th><th>Scan Name</th><th style="text-align:center">Status</th></tr></thead>
      <tbody>{scan_rows_html}</tbody>
    </table>
  </div>

  <h2>Compliance by OS</h2>
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th>OS</th>
          <th style="text-align:center">✅ Compliant</th>
          <th style="text-align:center">❌ Non-Compliant</th>
          <th style="text-align:center">⚠ Manual</th>
          <th style="text-align:center">Rate</th>
        </tr>
      </thead>
      <tbody>{os_rows_html}</tbody>
    </table>
  </div>

  <h2>Compliance Detail (Non-Compliant first)</h2>
  <div class="tbl-wrap">
    <table>
      <thead>
        <tr><th>#</th><th>Host</th><th>IP</th><th>OS</th><th>Status</th><th>Check</th></tr>
      </thead>
      <tbody>{detail_html}</tbody>
    </table>
  </div>

  <p class="footer">
    Ingram Micro — CIS Benchmark Automation &nbsp;·&nbsp; {stats['generated_at']}
  </p>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    log(f"HTML → {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def generate_report(rows: list[dict], scan_results: list[dict], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    stats    = summarise(rows, scan_results)

    print_summary(rows, scan_results, stats)

    write_csv(rows,             os.path.join(output_dir, f"cis_compliance_{date_str}.csv"))
    write_scan_summary_csv(scan_results, os.path.join(output_dir, f"cis_scan_summary_{date_str}.csv"))
    write_html(rows, scan_results, stats, os.path.join(output_dir, f"cis_compliance_{date_str}.html"))

    # Save JSON for downstream use
    with open(os.path.join(output_dir, f"cis_compliance_{date_str}.json"), "w") as f:
        json.dump({"stats": stats, "scan_results": scan_results, "rows": rows[:1000]}, f, indent=2)

    log(f"Report complete — all files in {output_dir}/")
