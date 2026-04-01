import os

# ── Tenable.io API ────────────────────────────────────────────────────────────
TENABLE_ACCESS_KEY = os.environ.get("TENABLE_ACCESS_KEY", "")
TENABLE_SECRET_KEY = os.environ.get("TENABLE_SECRET_KEY", "")
TENABLE_BASE       = "https://cloud.tenable.com"
TENABLE_HEADERS    = {
    "X-ApiKeys":    f"accessKey={TENABLE_ACCESS_KEY};secretKey={TENABLE_SECRET_KEY}",
    "Content-Type": "application/json",
    "Accept":       "application/json",
}

# ── ServiceNow CMDB API ───────────────────────────────────────────────────────
SNOW_INSTANCE  = os.environ.get("SNOW_INSTANCE", "")   # e.g. "company.service-now.com"
SNOW_USER      = os.environ.get("SNOW_USER", "")
SNOW_PASS      = os.environ.get("SNOW_PASS", "")
SNOW_BASE      = f"https://{SNOW_INSTANCE}/api/now"
# CMDB table that holds server/CI records
SNOW_CMDB_TABLE = os.environ.get("SNOW_CMDB_TABLE", "cmdb_ci_server")

# ── Fallback: CSV file in repo if ServiceNow not available ───────────────────
CMDB_CSV_PATH  = os.environ.get("CMDB_CSV_PATH", "input/cmdb_assets.csv")
# Expected columns: hostname, ip_address, os_name, os_version

# ── HTTP settings ─────────────────────────────────────────────────────────────
MAX_RETRIES    = int(os.getenv("MAX_RETRIES",    "5"))
POLL_INTERVAL  = int(os.getenv("POLL_INTERVAL",  "60"))   # seconds between scan status polls
MAX_POLL_WAIT  = int(os.getenv("MAX_POLL_WAIT",  "14400")) # 4h hard cap per scan

# ── Paths ─────────────────────────────────────────────────────────────────────
OUTPUT_DIR     = os.getenv("OUTPUT_DIR", "output")
INPUT_DIR      = os.getenv("INPUT_DIR",  "input")

# ── CIS Scan definitions (from document) ──────────────────────────────────────
# Maps OS key → Tenable scan name + agent group name
CIS_SCANS = {
    # Windows
    "Win-2012-R2-MS": {
        "scan_name":  "Agent-Win-2012-R2-MS-IM-Compliance",
        "group_name": "Ingram Micro-Win-2012R2-MS",
        "os_family":  "windows",
    },
    "Win-2012-R2-DC": {
        "scan_name":  "Agent-Win-2012-R2-DC-IM-Compliance",
        "group_name": "Ingram Micro-Win-2012R2-MS",   # uses same group per doc
        "os_family":  "windows",
    },
    "Win-2016-MS": {
        "scan_name":  "Agent-Win-2016-MS-IM-Compliance",
        "group_name": "Ingram Micro-Win-2016-MS",
        "os_family":  "windows",
    },
    "Win-2016-DC": {
        "scan_name":  "Agent-Win-2016-DC-IM-Compliance",
        "group_name": "Ingram Micro-Win-2016-DC",
        "os_family":  "windows",
    },
    "Win-2019-MS": {
        "scan_name":  "Agent-Win-2019-MS-IM-Compliance",
        "group_name": "Ingram Micro-Win-2019-MS",
        "os_family":  "windows",
    },
    "Win-2019-DC": {
        "scan_name":  "Agent-Win-2019-DC-IM-Compliance",
        "group_name": "Ingram Micro-Win-2019-DC",
        "os_family":  "windows",
    },
    "Win-2022-MS": {
        "scan_name":  "Agent-Win-2022-MS-IM-Compliance",
        "group_name": "Ingram Micro-Win-2022-MS",
        "os_family":  "windows",
    },
    "Win-2022-DC": {
        "scan_name":  "Agent-Win-2022-DC-IM-Compliance",
        "group_name": "Ingram Micro-Win-2022-DC",
        "os_family":  "windows",
    },
    # Linux
    "Debian-11": {
        "scan_name":  "Agent-Debian 11-IM-Compliance",
        "group_name": "Ingram Micro-Linux-Debian-11",
        "os_family":  "linux",
    },
    "SLES-15": {
        "scan_name":  "CIS-Compliance-Suse15",
        "group_name": "Ingram Micro-Linux-Suse15",
        "os_family":  "linux",
    },
    "RHEL-8": {
        "scan_name":  "Agent-RHEL-8-IM-Compliance",
        "group_name": "Ingram Micro-Linux-RHEL-8",
        "os_family":  "linux",
    },
    "Ubuntu-20": {
        "scan_name":  "Agent-Ubuntu-20-IM-Compliance",
        "group_name": "Ingram Micro-Linux-Ubuntu-20",
        "os_family":  "linux",
    },
    "Ubuntu-22": {
        "scan_name":  "Agent-Ubuntu-22-IM-Compliance",
        "group_name": "Ingram Micro-Linux-Ubuntu-22",
        "os_family":  "linux",
    },
    "CentOS-7": {
        "scan_name":  "Agent-Cent OS-7-IM-Compliance",
        "group_name": "Ingram Micro-Linux-CentOS-7",
        "os_family":  "linux",
    },
}

# ── OS string → CIS_SCANS key mapping ────────────────────────────────────────
# Used to match CMDB OS field to the right scan/group
OS_KEYWORD_MAP = {
    "windows server 2012 r2":  "Win-2012-R2-MS",
    "windows 2012 r2 ms":      "Win-2012-R2-MS",
    "windows 2012 r2 dc":      "Win-2012-R2-DC",
    "windows server 2016":     "Win-2016-MS",
    "windows 2016 ms":         "Win-2016-MS",
    "windows 2016 dc":         "Win-2016-DC",
    "windows server 2019":     "Win-2019-MS",
    "windows 2019 ms":         "Win-2019-MS",
    "windows 2019 dc":         "Win-2019-DC",
    "windows server 2022":     "Win-2022-MS",
    "windows 2022 ms":         "Win-2022-MS",
    "windows 2022 dc":         "Win-2022-DC",
    "debian 11":               "Debian-11",
    "debian11":                "Debian-11",
    "sles 15":                 "SLES-15",
    "suse 15":                 "SLES-15",
    "suse15":                  "SLES-15",
    "rhel 8":                  "RHEL-8",
    "red hat 8":               "RHEL-8",
    "redhat 8":                "RHEL-8",
    "ubuntu 20":               "Ubuntu-20",
    "ubuntu20":                "Ubuntu-20",
    "ubuntu 22":               "Ubuntu-22",
    "ubuntu22":                "Ubuntu-22",
    "centos 7":                "CentOS-7",
    "centos7":                 "CentOS-7",
}
