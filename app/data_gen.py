"""Generate 6 canonical CSVs with planted execution gaps and negative space."""

from __future__ import annotations

import os
import random
from datetime import datetime, timedelta

import pandas as pd

RNG = random.Random(42)
NOW = datetime(2026, 9, 20, 12, 0, 0)
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "sample")

ENTITIES = [
    # id, name, sector, size, quality  (quality 0=bad, 1=good)
    ("CSE-07", "BFSI-East Clearing DC", "BFSI", "L", 0.15),
    ("CSE-19", "Energy-ER Grid SOC", "Energy", "L", 0.25),
    ("CSE-03", "Telecom Core NOC", "Telecom", "L", 0.40),
    ("CSE-22", "Power-East Transmission", "Power", "M", 0.45),
    ("CSE-11", "Transport Rail OCC", "Transport", "M", 0.50),
    ("CSE-14", "Oil & Gas Pipeline", "Energy", "M", 0.55),
    ("CSE-05", "Healthcare-N EMR", "Healthcare", "M", 0.60),
    ("CSE-21", "Strategic Facility", "Strategic", "S", 0.62),
    ("CSE-02", "Telecom-South RAN", "Telecom", "M", 0.70),
    ("CSE-09", "Healthcare-East Labs", "Healthcare", "S", 0.75),
    ("CSE-08", "BFSI-West Payments", "BFSI", "L", 0.88),
    ("CSE-16", "Power-North Generation", "Power", "L", 0.90),
]

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEV_W = [0.08, 0.18, 0.42, 0.32]
ALERT_TYPES = [
    ("Malware", "TA0002"),
    ("Phishing", "TA0001"),
    ("Brute Force", "TA0006"),
    ("Lateral Movement", "TA0008"),
    ("Exfiltration", "TA0010"),
    ("Privilege Escalation", "TA0004"),
    ("C2 Beacon", "TA0011"),
    ("Policy Violation", "TA0005"),
    ("Suspicious Login", "TA0001"),
    ("Data Access Anomaly", "TA0009"),
]
DISPOSITIONS = ["Closed", "Closed", "Closed", "Escalated", "Open"]
TEMPLATES = [
    "Reviewed alert. No malicious activity observed. Closed as false positive per SOP.",
    "Checked logs. User confirmed activity. Closing ticket. No further action.",
    "Alert validated. Endpoint isolated. Waiting for IR. Update later.",
    "Duplicate of previous case. Linked and closed. No root cause required.",
]


def _pick(seq, w=None):
    if w is None:
        return RNG.choice(seq)
    r = RNG.random()
    acc = 0.0
    for x, p in zip(seq, w):
        acc += p
        if r <= acc:
            return x
    return seq[-1]


def generate(out_dir: str = DATA_DIR) -> str:
    os.makedirs(out_dir, exist_ok=True)
    analysts, assets, alerts, cases, playbooks, compliance = [], [], [], [], [], []
    planted = []

    for cap in [
        "Threat Detection",
        "Investigation",
        "Escalation",
        "Incident Response",
        "Security Operations",
        "Governance",
        "Operational Discipline",
        "Cyber Resilience",
    ]:
        playbooks.append(
            {
                "playbook_id": f"PB-{cap[:3].upper()}-01",
                "name": f"{cap} playbook",
                "steps": 6 if cap != "Investigation" else 8,
                "expected_escalation": cap in ("Escalation", "Incident Response"),
                "sop_reference": "SOP 4.2" if cap in ("Investigation", "Escalation") else "SOP 3.1",
                "capability": cap,
            }
        )
        compliance.append(
            {
                "control_id": f"CTL-{cap[:3].upper()}",
                "description": f"Expected evidence of {cap.lower()} on critical assets",
                "expected_behavior": "alerts_or_cases_present",
                "capability_mapping": cap,
            }
        )

    aid = 1
    cid = 1
    asid = 1
    for ent_id, ent_name, sector, size, quality in ENTITIES:
        n_analysts = 8 if size == "L" else 5 if size == "M" else 3
        team_ids = []
        for i in range(n_analysts):
            analyst_id = f"AN-{ent_id}-{i+1:02d}"
            team_ids.append(analyst_id)
            analysts.append(
                {
                    "analyst_id": analyst_id,
                    "name": f"Analyst {i+1} {ent_id}",
                    "team": ent_id,
                    "entity_id": ent_id,
                    "experience_years": RNG.randint(1, 12),
                    "cases_handled": 0,
                    "avg_mttr": 0,
                    "template_rate": 0.0,
                }
            )

        n_assets = 40 if size == "L" else 28 if size == "M" else 16
        ent_assets = []
        for i in range(n_assets):
            crit = _pick(["Critical", "High", "Medium", "Low"], [0.15, 0.25, 0.35, 0.25])
            atype = _pick(["Server", "Workstation", "DC", "Network", "OT", "Cloud"])
            asset_id = f"AST-{ent_id}-{i+1:03d}"
            ent_assets.append((asset_id, crit, atype))
            assets.append(
                {
                    "asset_id": asset_id,
                    "name": f"{ent_name} {atype} {i+1:03d}",
                    "entity_id": ent_id,
                    "entity_name": ent_name,
                    "sector": sector,
                    "criticality": crit,
                    "type": atype,
                    "last_alert_timestamp": "",
                }
            )

        # Planted silent critical assets (NS-01) on bad energy/bfsi
        silent_ids = set()
        if ent_id in ("CSE-19", "CSE-07"):
            silent = [a for a in ent_assets if a[1] == "Critical"][:4]
            silent_ids = {a[0] for a in silent}
            for a in silent:
                planted.append({"kind": "NS-01", "entity_id": ent_id, "asset_id": a[0]})

        n_alerts = {"L": 420, "M": 260, "S": 140}[size]
        # Low activity anomaly (NS-04) for CSE-11
        if ent_id == "CSE-11":
            n_alerts = 35
            planted.append({"kind": "NS-04", "entity_id": ent_id})

        # Missing MITRE category (NS-02) — no Lateral Movement in CSE-03
        drop_lateral = ent_id == "CSE-03"
        if drop_lateral:
            planted.append({"kind": "NS-02", "entity_id": ent_id, "category": "Lateral Movement"})

        no_night = ent_id == "CSE-11"
        if no_night:
            planted.append({"kind": "NS-07", "entity_id": ent_id})

        template_analyst = team_ids[0] if quality < 0.35 else None
        if template_analyst:
            planted.append({"kind": "EG-03", "entity_id": ent_id, "analyst_id": template_analyst})

        for _ in range(n_alerts):
            asset_id, crit, atype = _pick(ent_assets)
            if asset_id in silent_ids:
                continue
            atype_name, mitre = _pick(ALERT_TYPES)
            if drop_lateral and atype_name == "Lateral Movement":
                atype_name, mitre = "Phishing", "TA0001"
            sev = _pick(SEVERITIES, SEV_W)
            day = RNG.randint(0, 29)
            hour = RNG.randint(0, 23)
            if no_night:
                hour = RNG.randint(9, 17)
            ts = NOW - timedelta(days=day, hours=hour, minutes=RNG.randint(0, 59))
            analyst = _pick(team_ids)
            # quality drives investigation depth
            if RNG.random() > quality and sev in ("Critical", "High"):
                dwell = RNG.randint(2, 9)
                steps = RNG.randint(0, 1)
                esc = False
                disp = "Closed"
            else:
                dwell = RNG.randint(15, 180) if sev in ("Critical", "High") else RNG.randint(20, 240)
                steps = RNG.randint(3, 9)
                esc = sev == "Critical" and RNG.random() < (0.85 if quality > 0.5 else 0.25)
                disp = "Escalated" if esc else _pick(["Closed", "Closed", "Open"])

            # Explicit EG-01 plant on CSE-07
            if ent_id == "CSE-07" and sev == "Critical" and RNG.random() < 0.55:
                dwell, steps, esc, disp = RNG.randint(2, 8), RNG.randint(0, 1), False, "Closed"
                planted.append({"kind": "EG-01", "entity_id": ent_id, "alert_id": f"AL-{aid:06d}"})

            notes = (
                TEMPLATES[RNG.randint(0, 1)]
                if analyst == template_analyst
                else (
                    f"Investigated {atype_name} on {asset_id}. Pulled IOCs, reviewed {steps} artefacts, "
                    f"{'escalated to IR' if esc else 'contained locally'}. Root cause documented."
                )
            )
            if ent_id == "CSE-07" and sev == "Critical" and steps < 2:
                notes = "Closed as false positive."  # EG-09 incomplete docs

            alert_id = f"AL-{aid:06d}"
            aid += 1
            alerts.append(
                {
                    "alert_id": alert_id,
                    "entity_id": ent_id,
                    "timestamp": ts.isoformat(),
                    "severity": sev,
                    "asset_id": asset_id,
                    "alert_type": atype_name,
                    "mitre_tactic": mitre,
                    "disposition": disp,
                    "analyst_id": analyst,
                    "dwell_time": dwell,
                    "investigation_steps": steps,
                    "escalation": esc,
                    "source_file_hash": "",
                }
            )
            if disp != "Open":
                case_id = f"CS-{cid:06d}"
                cid += 1
                closure = ts + timedelta(minutes=dwell)
                cases.append(
                    {
                        "case_id": case_id,
                        "alert_ids": alert_id,
                        "entity_id": ent_id,
                        "creation_timestamp": ts.isoformat(),
                        "closure_timestamp": closure.isoformat(),
                        "analyst_id": analyst,
                        "status": "Closed" if disp == "Closed" else disp,
                        "closure_notes": notes,
                        "root_cause": "" if steps < 2 else f"{atype_name} on {asset_id}",
                        "remediation": "" if steps < 2 else "patched / blocked",
                    }
                )

        # last_alert_timestamp
        by_asset = {}
        for a in alerts:
            if a["entity_id"] != ent_id:
                continue
            by_asset.setdefault(a["asset_id"], a["timestamp"])
            if a["timestamp"] > by_asset[a["asset_id"]]:
                by_asset[a["asset_id"]] = a["timestamp"]
        for row in assets:
            if row["entity_id"] == ent_id:
                row["last_alert_timestamp"] = by_asset.get(row["asset_id"], "")

    # Repeated alert no RCA (EG-04) on CSE-19
    asset = next(a["asset_id"] for a in assets if a["entity_id"] == "CSE-19" and a["criticality"] == "High")
    for k in range(6):
        ts = NOW - timedelta(days=k)
        alert_id = f"AL-{aid:06d}"
        aid += 1
        alerts.append(
            {
                "alert_id": alert_id,
                "entity_id": "CSE-19",
                "timestamp": ts.isoformat(),
                "severity": "High",
                "asset_id": asset,
                "alert_type": "Malware",
                "mitre_tactic": "TA0002",
                "disposition": "Closed",
                "analyst_id": "AN-CSE-19-01",
                "dwell_time": 12,
                "investigation_steps": 1,
                "escalation": False,
                "source_file_hash": "",
            }
        )
        planted.append({"kind": "EG-04", "entity_id": "CSE-19", "alert_id": alert_id})

    entities = [
        {
            "entity_id": e[0],
            "entity_name": e[1],
            "sector": e[2],
            "size": e[3],
        }
        for e in ENTITIES
    ]

    pd.DataFrame(alerts).to_csv(os.path.join(out_dir, "alerts.csv"), index=False)
    pd.DataFrame(cases).to_csv(os.path.join(out_dir, "cases.csv"), index=False)
    pd.DataFrame(assets).to_csv(os.path.join(out_dir, "assets.csv"), index=False)
    pd.DataFrame(analysts).to_csv(os.path.join(out_dir, "analysts.csv"), index=False)
    pd.DataFrame(playbooks).to_csv(os.path.join(out_dir, "playbooks.csv"), index=False)
    pd.DataFrame(compliance).to_csv(os.path.join(out_dir, "compliance.csv"), index=False)
    pd.DataFrame(entities).to_csv(os.path.join(out_dir, "entities.csv"), index=False)
    pd.DataFrame(planted).to_csv(os.path.join(out_dir, "ground_truth.csv"), index=False)
    return out_dir


if __name__ == "__main__":
    print(generate())
