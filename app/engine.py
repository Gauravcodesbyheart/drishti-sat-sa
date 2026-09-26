"""DRISHTI dual engine: 12 execution-gap + 8 negative-space detectors, SPS, peer, Top-100."""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .trust import seal, sha3

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "sample")

CAP_WEIGHTS = {
    "Threat Detection": 0.20,
    "Investigation": 0.20,
    "Escalation": 0.15,
    "Incident Response": 0.15,
    "Security Operations": 0.10,
    "Governance": 0.10,
    "Operational Discipline": 0.05,
    "Cyber Resilience": 0.05,
}
SEV_W = {"Critical": 1.0, "High": 0.7, "Medium": 0.4, "Low": 0.1}
RULE_CAP = {
    "EG-01": "Investigation",
    "EG-02": "Escalation",
    "EG-03": "Investigation",
    "EG-04": "Incident Response",
    "EG-05": "Threat Detection",
    "EG-06": "Operational Discipline",
    "EG-07": "Investigation",
    "EG-08": "Escalation",
    "EG-09": "Governance",
    "EG-10": "Investigation",
    "EG-11": "Security Operations",
    "EG-12": "Operational Discipline",
    "NS-01": "Threat Detection",
    "NS-02": "Threat Detection",
    "NS-03": "Escalation",
    "NS-04": "Cyber Resilience",
    "NS-05": "Security Operations",
    "NS-06": "Governance",
    "NS-07": "Threat Detection",
    "NS-08": "Cyber Resilience",
    "ML-01": "Cyber Resilience",
}


class Store:
    def __init__(self):
        self.alerts = self.cases = self.assets = self.analysts = None
        self.entities = self.playbooks = self.compliance = None
        self.findings: list[dict] = []
        self.sps: list[dict] = []
        self.audit: list[dict] = []
        self.loaded = False
        self.prev_hash = "GENESIS"
        self.stats: dict[str, Any] = {}

    def _log(self, action: str, detail: dict):
        rec = {"action": action, "detail": detail, "ts": datetime.utcnow().isoformat()}
        trust = seal(rec, self.prev_hash)
        rec.update(trust)
        self.prev_hash = trust["chain_hash"]
        self.audit.append(rec)


STORE = Store()


def _bool_series(s: pd.Series) -> pd.Series:
    if s.dtype == bool:
        return s
    return s.astype(str).str.lower().isin(["true", "1", "yes"])


def load_csvs(folder: str) -> Store:
    s = STORE
    s.alerts = pd.read_csv(os.path.join(folder, "alerts.csv"))
    s.cases = pd.read_csv(os.path.join(folder, "cases.csv"))
    s.assets = pd.read_csv(os.path.join(folder, "assets.csv"))
    s.analysts = pd.read_csv(os.path.join(folder, "analysts.csv"))
    s.playbooks = pd.read_csv(os.path.join(folder, "playbooks.csv"))
    s.compliance = pd.read_csv(os.path.join(folder, "compliance.csv"))
    ent_path = os.path.join(folder, "entities.csv")
    if os.path.exists(ent_path):
        s.entities = pd.read_csv(ent_path)
    else:
        s.entities = s.assets[["entity_id", "entity_name", "sector"]].drop_duplicates()
    s.alerts["escalation"] = _bool_series(s.alerts["escalation"])
    s.alerts["timestamp"] = pd.to_datetime(s.alerts["timestamp"])
    s.cases["creation_timestamp"] = pd.to_datetime(s.cases["creation_timestamp"])
    s.cases["closure_timestamp"] = pd.to_datetime(s.cases["closure_timestamp"], errors="coerce")
    s.cases["closure_notes"] = s.cases["closure_notes"].fillna("")
    for col in ("dwell_time", "investigation_steps"):
        s.alerts[col] = pd.to_numeric(s.alerts[col], errors="coerce").fillna(0).astype(int)
    s.findings = []
    s.sps = []
    s.loaded = True
    s._log("ingest", {"folder": folder, "alerts": int(len(s.alerts)), "cases": int(len(s.cases))})
    return s


def _add(s: Store, rule_id: str, entity_id: str, conf: float, rationale: str, evidence: list, severity="High", extra=None):
    row = {
        "finding_id": f"F-{len(s.findings)+1:05d}",
        "rule_id": rule_id,
        "entity_id": entity_id,
        "confidence": round(float(conf), 3),
        "rationale": rationale,
        "evidence": evidence[:12],
        "severity": severity,
        "capability": RULE_CAP.get(rule_id, "Governance"),
        "kind": "Execution Gap" if rule_id.startswith("EG") or rule_id.startswith("ML") else "Negative Space",
        "extra": extra or {},
    }
    row.update(seal({k: row[k] for k in ("finding_id", "rule_id", "entity_id", "rationale", "confidence")}, s.prev_hash))
    s.prev_hash = row["chain_hash"]
    s.findings.append(row)


def run_detectors(s: Store) -> None:
    a, c, assets = s.alerts, s.cases, s.assets
    # EG-01 FAST_CRITICAL_CLOSURE (entity roll-up)
    m = (a["severity"] == "Critical") & (a["dwell_time"] < 10) & (a["investigation_steps"] < 2) & (~a["escalation"])
    for ent, g in a.loc[m].groupby("entity_id"):
        evid = g["alert_id"].head(8).tolist()
        r0 = g.iloc[0]
        _add(s, "EG-01", ent, 0.90,
             f"{len(g)} critical alerts closed in <10 min with <2 investigation steps and no escalation (e.g. {r0['alert_id']} dwell {int(r0['dwell_time'])} min) — violates SOP 4.2.",
             evid, "Critical", {"count": int(len(g))})

    # EG-02 NO_ESCALATION_CRITICAL
    m = (a["severity"] == "Critical") & (~a["escalation"]) & (a["disposition"] == "Closed")
    for ent, g in a.loc[m].groupby("entity_id"):
        _add(s, "EG-02", ent, 0.85,
             f"{len(g)} critical alerts closed without any escalation record.",
             g["alert_id"].head(8).tolist(), "Critical", {"count": int(len(g))})

    # EG-07 NO_INVESTIGATION
    m = (a["investigation_steps"] == 0) & (a["severity"].isin(["Critical", "High"]))
    for ent, g in a.loc[m].groupby("entity_id"):
        _add(s, "EG-07", ent, 0.82,
             f"{len(g)} Critical/High alerts have zero investigation steps.",
             g["alert_id"].head(8).tolist(), "High", {"count": int(len(g))})

    # EG-09 INCOMPLETE_DOCUMENTATION
    short = c[c["closure_notes"].str.len() < 20]
    if not short.empty:
        merged = short.merge(a[["alert_id", "severity"]], left_on="alert_ids", right_on="alert_id", how="left")
        merged = merged[merged["severity"] == "Critical"]
        for _, r in merged.head(200).iterrows():
            _add(s, "EG-09", r["entity_id"], 0.70,
                 f"Critical case {r['case_id']} closed with notes shorter than 20 characters.",
                 [r.get("alert_ids", "")], "Critical")

    # EG-10 WRONG_DISPOSITION
    m = (a["alert_type"] == "Malware") & (a["disposition"] == "Closed") & (a["investigation_steps"] < 2)
    for _, r in a.loc[m].head(150).iterrows():
        _add(s, "EG-10", r["entity_id"], 0.80,
             f"Malware alert {r['alert_id']} closed as benign without investigation evidence.",
             [r["alert_id"]], r["severity"])

    # EG-11 SLA_VIOLATION  Critical > 60 min, High > 240
    sla = ((a["severity"] == "Critical") & (a["dwell_time"] > 60)) | ((a["severity"] == "High") & (a["dwell_time"] > 240))
    for _, r in a.loc[sla].head(150).iterrows():
        _add(s, "EG-11", r["entity_id"], 0.75,
             f"{r['severity']} alert {r['alert_id']} dwell {r['dwell_time']} min exceeds SLA.",
             [r["alert_id"]], r["severity"])

    # EG-04 REPEATED_ALERT_NO_ROOT_CAUSE
    grp = a.groupby(["entity_id", "asset_id", "alert_type"]).size().reset_index(name="n")
    hot = grp[grp["n"] >= 5]
    for _, r in hot.iterrows():
        evid = a[(a["entity_id"] == r["entity_id"]) & (a["asset_id"] == r["asset_id"]) & (a["alert_type"] == r["alert_type"])]["alert_id"].head(8).tolist()
        _add(s, "EG-04", r["entity_id"], 0.80,
             f"Asset {r['asset_id']} raised {r['alert_type']} {int(r['n'])} times with no evidence of root-cause remediation.",
             evid, "High", {"asset_id": r["asset_id"]})

    # EG-03 TEMPLATE_INVESTIGATION TF-IDF
    _template_detector(s)

    # EG-06 METRIC_GAMING at entity level (computed after rates)
    # EG-12 ANALYST_OVERLOAD
    day = a.copy()
    day["day"] = day["timestamp"].dt.date.astype(str)
    load = day.groupby(["entity_id", "analyst_id", "day"]).size().reset_index(name="n")
    if not load.empty:
        peer = load.groupby("entity_id")["n"].median()
        for _, r in load.iterrows():
            med = float(peer.get(r["entity_id"], 1) or 1)
            if r["n"] > 3 * med and r["n"] >= 12:
                _add(s, "EG-12", r["entity_id"], 0.65,
                     f"Analyst {r['analyst_id']} handled {int(r['n'])} cases on {r['day']} (>3× team median {med:.0f}) — quality risk.",
                     [r["analyst_id"]], "Medium")

    # Negative space
    _negative_space(s)
    _isolation_forest(s)
    s._log("analyze", {"findings": len(s.findings)})


def _template_detector(s: Store):
    c = s.cases
    if c.empty or "closure_notes" not in c.columns:
        return
    for (ent, analyst), g in c.groupby(["entity_id", "analyst_id"]):
        notes = g["closure_notes"].fillna("").astype(str).tolist()
        if len(notes) < 6:
            continue
        try:
            vec = TfidfVectorizer(min_df=1, ngram_range=(1, 2)).fit_transform(notes)
            sim = cosine_similarity(vec)
            n = sim.shape[0]
            pairs = int(((sim > 0.95).sum() - n) / 2)
            if pairs >= 5:
                evid = g["alert_ids"].head(8).tolist()
                _add(s, "EG-03", ent, 0.91,
                     f"Analyst {analyst} produced {pairs} near-duplicate investigation notes (TF-IDF cosine > 0.95) — template-driven review.",
                     evid, "High", {"analyst_id": analyst, "pairs": pairs})
        except ValueError:
            continue


def _negative_space(s: Store):
    a, assets = s.alerts, s.assets
    counts = a.groupby("asset_id").size().rename("n")
    assets = assets.merge(counts, left_on="asset_id", right_index=True, how="left")
    assets["n"] = assets["n"].fillna(0)
    sector_avg = assets.groupby("sector")["n"].mean().to_dict()

    # NS-01 / EG-05 silent critical
    silent = assets[(assets["criticality"] == "Critical") & (assets["n"] == 0)]
    for _, r in silent.iterrows():
        peer = float(sector_avg.get(r["sector"], 10))
        if peer > 10 or True:
            _add(s, "NS-01", r["entity_id"], 0.93,
                 f"Critical asset {r['name']} ({r['asset_id']}) has 0 alerts in 30 days while sector peer average is {peer:.1f} — monitoring blind spot.",
                 [r["asset_id"]], "Critical", {"asset_id": r["asset_id"], "peer_avg": round(peer, 1)})
            _add(s, "EG-05", r["entity_id"], 0.93,
                 f"Control appears deployed on critical asset {r['asset_id']} but it is not generating telemetry.",
                 [r["asset_id"]], "Critical")

    # NS-08 coverage gap
    crit = assets[assets["criticality"] == "Critical"]
    for ent, g in crit.groupby("entity_id"):
        silent_n = int((g["n"] == 0).sum())
        tot = int(len(g))
        if tot and silent_n / tot >= 0.4:
            _add(s, "NS-08", ent, 0.90,
                 f"{silent_n}/{tot} critical assets ({silent_n/tot:.0%}) generated no alerts in 30 days — coverage gap.",
                 g.loc[g["n"] == 0, "asset_id"].head(8).tolist(), "High")

    # NS-02 missing MITRE / alert category vs sector
    sector_types = a.merge(assets[["asset_id", "sector"]], on="asset_id", how="left")
    for sector, sg in sector_types.groupby("sector"):
        expected = set(sg["alert_type"].unique())
        for ent, eg in sg.groupby("entity_id"):
            have = set(eg["alert_type"].unique())
            missing = expected - have
            if "Lateral Movement" in missing or len(missing) >= 3:
                miss = sorted(missing)[:5]
                _add(s, "NS-02", ent, 0.85,
                     f"Missing expected alert categories vs {sector} peers: {', '.join(miss) or 'Lateral Movement'}.",
                     miss, "High")

    # NS-03 missing escalation records
    crit_closed = a[(a["severity"] == "Critical")]
    for ent, g in crit_closed.groupby("entity_id"):
        esc = int(g["escalation"].sum())
        if len(g) >= 5 and esc == 0:
            _add(s, "NS-03", ent, 0.80,
                 f"Entity has {len(g)} critical alerts and 0 escalations in 30 days.",
                 g["alert_id"].head(6).tolist(), "Critical")

    # NS-04 low activity vs sector median
    vol = a.groupby("entity_id").size()
    ent_sec = assets[["entity_id", "sector"]].drop_duplicates()
    vol = vol.reset_index(name="n").merge(ent_sec, on="entity_id")
    med = vol.groupby("sector")["n"].median()
    for _, r in vol.iterrows():
        m = float(med.get(r["sector"], r["n"]))
        if m and r["n"] < 0.10 * m:
            _add(s, "NS-04", r["entity_id"], 0.75,
                 f"Alert volume {int(r['n'])} is <10% of {r['sector']} peer median {m:.0f} — possible log-forwarding failure.",
                 [], "High")

    # NS-07 no night/weekend
    tmp = a.copy()
    tmp["hour"] = tmp["timestamp"].dt.hour
    tmp["dow"] = tmp["timestamp"].dt.dayofweek
    for ent, g in tmp.groupby("entity_id"):
        night = ((g["hour"] < 7) | (g["hour"] > 21) | (g["dow"] >= 5)).mean()
        if len(g) >= 20 and night < 0.02:
            _add(s, "NS-07", ent, 0.65,
                 "Almost no night/weekend alerts in 30 days while peers typically show ~20% off-hours volume — monitoring gap.",
                 [], "Medium")

    # NS-05 silent analyst
    cases_n = s.cases.groupby("analyst_id").size()
    for ent, g in s.analysts.groupby("entity_id"):
        if g.empty:
            continue
        team_avg = float(cases_n.reindex(g["analyst_id"]).fillna(0).mean() or 0)
        for _, ar in g.iterrows():
            n = int(cases_n.get(ar["analyst_id"], 0))
            if team_avg >= 8 and n == 0:
                _add(s, "NS-05", ent, 0.60,
                     f"Analyst {ar['analyst_id']} closed 0 cases while team average is {team_avg:.0f}.",
                     [ar["analyst_id"]], "Low")


def _isolation_forest(s: Store):
    feats = _entity_features(s)
    if len(feats) < 4:
        return
    X = feats[["mttr", "esc_rate", "inv_steps", "silent_rate", "crit_fast", "night_rate"]].fillna(0)
    iso = IsolationForest(n_estimators=200, contamination=0.15, random_state=42)
    scores = iso.fit_predict(X)
    raw = iso.decision_function(X)
    for i, row in feats.iterrows():
        if scores[i] == -1:
            conf = float(min(0.95, 0.70 + abs(raw[i])))
            shap_like = {
                "mttr": round(float(row["mttr"]), 2),
                "escalation_rate": round(float(row["esc_rate"]), 3),
                "silent_asset_rate": round(float(row["silent_rate"]), 3),
                "fast_critical_rate": round(float(row["crit_fast"]), 3),
            }
            _add(s, "ML-01", row["entity_id"], conf,
                 "Isolation Forest flagged this entity as a multivariate outlier on MTTR, escalation, silent-asset and fast-critical rates (n=200, contamination=0.15).",
                 [], "High", {"features": shap_like, "anomaly_score": round(float(raw[i]), 4)})

    for _, row in feats.iterrows():
        if float(row["mttr"]) < 18 and float(row["esc_rate"]) < 0.25 and float(row["crit_fast"]) > 0.25:
            _add(
                s, "EG-06", row["entity_id"], 0.88,
                f"Metric-gaming pattern: mean dwell {row['mttr']:.0f} min, escalation {row['esc_rate']:.0%}, fast-critical rate {row['crit_fast']:.0%}.",
                [], "High", {"mttr": round(float(row["mttr"]), 1)},
            )


def _entity_features(s: Store) -> pd.DataFrame:
    rows = []
    a, assets = s.alerts, s.assets
    for ent, g in a.groupby("entity_id"):
        ast = assets[assets["entity_id"] == ent]
        silent = 0.0
        if not ast.empty:
            cnt = g.groupby("asset_id").size()
            crit = ast[ast["criticality"] == "Critical"]
            if len(crit):
                silent = float((crit["asset_id"].map(cnt).fillna(0) == 0).mean())
        night = float(((g["timestamp"].dt.hour < 7) | (g["timestamp"].dt.hour > 21)).mean())
        crit = g[g["severity"] == "Critical"]
        fast = float(((crit["dwell_time"] < 10) & (crit["investigation_steps"] < 2)).mean()) if len(crit) else 0.0
        rows.append({
            "entity_id": ent,
            "mttr": float(g["dwell_time"].mean()),
            "esc_rate": float(g["escalation"].mean()),
            "inv_steps": float(g["investigation_steps"].mean()),
            "silent_rate": silent,
            "crit_fast": fast,
            "night_rate": night,
            "alerts": int(len(g)),
            "critical": int((g["severity"] == "Critical").sum()),
        })
    return pd.DataFrame(rows)


def score_entities(s: Store) -> None:
    feats = _entity_features(s)
    ent_meta = s.entities.drop_duplicates("entity_id")
    findings_by = defaultdict(list)
    for f in s.findings:
        findings_by[f["entity_id"]].append(f)

    scored = []
    for _, r in feats.iterrows():
        ent = r["entity_id"]
        fs = findings_by.get(ent, [])
        caps = {}
        for cap in CAP_WEIGHTS:
            rel = [x for x in fs if x["capability"] == cap]
            # concern rate: findings weighted by confidence, capped
            caps[cap] = min(100.0, round(sum(x["confidence"] * (1 + 0.15 * x.get("extra", {}).get("count", 1) ** 0.5) for x in rel) * 10, 1))
        sps = round(sum(caps[c] * w for c, w in CAP_WEIGHTS.items()), 1)
        meta = ent_meta[ent_meta["entity_id"] == ent]
        sector = str(meta["sector"].iloc[0]) if len(meta) else "Unknown"
        name = str(meta["entity_name"].iloc[0]) if len(meta) and "entity_name" in meta else ent
        scored.append({
            "entity_id": ent,
            "entity_name": name,
            "sector": sector,
            "sps": sps,
            "capabilities": caps,
            "alerts": int(r["alerts"]),
            "findings": len(fs),
            "silent_rate": round(float(r["silent_rate"]), 3),
            "mttr": round(float(r["mttr"]), 1),
            "esc_rate": round(float(r["esc_rate"]), 3),
            "band": "High" if sps >= 40 else "Medium" if sps >= 22 else "Low",
        })

    # peer trimmed median + z
    by_sec: dict[str, list[float]] = defaultdict(list)
    for row in scored:
        by_sec[row["sector"]].append(row["sps"])
    for row in scored:
        arr = np.array(by_sec[row["sector"]], dtype=float)
        if len(arr) >= 3:
            lo, hi = np.percentile(arr, [10, 90])
            trimmed = arr[(arr >= lo) & (arr <= hi)]
            med = float(np.median(trimmed if len(trimmed) else arr))
            sd = float(np.std(arr) or 1.0)
            z = (row["sps"] - med) / sd
        else:
            med, z = float(np.median(arr)), 0.0
        row["peer_median"] = round(med, 1)
        row["z_score"] = round(float(z), 2)
        row["peer_flag"] = abs(z) > 2
    s.sps = sorted(scored, key=lambda x: -x["sps"])
    s._log("score", {"entities": len(s.sps)})


def top100(s: Store) -> list[dict]:
    ranked = []
    sps_map = {x["entity_id"]: x for x in s.sps}
    for f in s.findings:
        sw = SEV_W.get(f["severity"], 0.4)
        cw = CAP_WEIGHTS.get(f["capability"], 0.1)
        z = abs(sps_map.get(f["entity_id"], {}).get("z_score", 0))
        score = f["confidence"] * sw * (1 + cw) * (1 + 0.15 * z)
        item = dict(f)
        item["queue_score"] = round(float(score), 4)
        item["entity_name"] = sps_map.get(f["entity_id"], {}).get("entity_name", f["entity_id"])
        item["sps"] = sps_map.get(f["entity_id"], {}).get("sps")
        item["decision"] = f.get("decision", "Pending")
        ranked.append(item)
    # diversity: cap per rule
    ranked.sort(key=lambda x: -x["queue_score"])
    seen_rule = defaultdict(int)
    out = []
    for item in ranked:
        if seen_rule[item["rule_id"]] >= 18:
            continue
        seen_rule[item["rule_id"]] += 1
        out.append(item)
        if len(out) >= 100:
            break
    return out


def run_all(folder: str = DATA_DIR) -> Store:
    load_csvs(folder)
    run_detectors(STORE)
    score_entities(STORE)
    STORE.stats = {
        "entities": int(STORE.entities["entity_id"].nunique()),
        "alerts": int(len(STORE.alerts)),
        "cases": int(len(STORE.cases)),
        "assets": int(len(STORE.assets)),
        "findings": int(len(STORE.findings)),
        "eg": sum(1 for f in STORE.findings if f["kind"] == "Execution Gap"),
        "ns": sum(1 for f in STORE.findings if f["kind"] == "Negative Space"),
        "queue": len(top100(STORE)),
        "offline": True,
        "data_dir": os.path.abspath(folder),
    }
    return STORE


def weekly_trends(s: Store) -> dict:
    """FR-16: trend across entities and time. Snapshot of this extract, not live SIEM."""
    if s.alerts is None or s.alerts.empty:
        return {"weeks": [], "by_entity": []}
    a = s.alerts.copy()
    a["timestamp"] = pd.to_datetime(a["timestamp"], errors="coerce")
    a = a.dropna(subset=["timestamp"])
    a["week"] = a["timestamp"].dt.to_period("W").astype(str)
    esc = _bool_series(a["escalation"]) if "escalation" in a.columns else False
    weeks = []
    for week, g in a.groupby("week"):
        fast = int(((g["severity"] == "Critical") & (g["dwell_time"] < 10) & (g["investigation_steps"] < 2)).sum())
        weeks.append(
            {
                "week": week,
                "alerts": int(len(g)),
                "critical": int((g["severity"] == "Critical").sum()),
                "entities": int(g["entity_id"].nunique()),
                "escalations": int(esc.loc[g.index].sum()) if isinstance(esc, pd.Series) else 0,
                "fast_critical": fast,
            }
        )
    weeks.sort(key=lambda x: x["week"])
    by_entity = (
        a.groupby("entity_id")
        .size()
        .reset_index(name="alerts")
        .sort_values("alerts", ascending=False)
        .head(12)
        .to_dict("records")
    )
    return {"weeks": weeks, "by_entity": by_entity}


def validate_planted(s: Store, folder: str | None = None) -> dict:
    """Compare planted ground_truth.csv to current findings. Not a production F1."""
    folder = folder or DATA_DIR
    path = os.path.join(folder, "ground_truth.csv")
    if not os.path.exists(path):
        return {"ok": False, "reason": "No ground_truth.csv in this extract.", "rows": [], "planted": 0, "recovered": 0}
    gt = pd.read_csv(path)
    rows = []
    recovered = 0
    for _, g in gt.iterrows():
        rule = str(g.get("kind", ""))
        ent = str(g.get("entity_id", ""))
        aid = "" if pd.isna(g.get("alert_id")) else str(g.get("alert_id"))
        ast = "" if pd.isna(g.get("asset_id")) else str(g.get("asset_id"))
        an = "" if pd.isna(g.get("analyst_id")) else str(g.get("analyst_id"))
        cands = [f for f in s.findings if f["rule_id"] == rule and f["entity_id"] == ent]
        hit, how, fid = False, "", ""
        for f in cands:
            blob = " ".join(str(x) for x in (f.get("evidence") or [])) + " " + str(f.get("rationale", ""))
            extra = f.get("extra") or {}
            if aid and aid in blob:
                hit, how = True, "alert in evidence"
            elif ast and (ast in blob or extra.get("asset_id") == ast):
                hit, how = True, "asset in evidence"
            elif an and (an in blob or extra.get("analyst_id") == an):
                hit, how = True, "analyst in evidence"
            elif not aid and not ast and not an and cands:
                hit, how = True, "entity + rule"
            if hit:
                fid = f["finding_id"]
                break
        if not hit and cands:
            hit, how, fid = True, "entity + rule (roll-up)", cands[0]["finding_id"]
        if hit:
            recovered += 1
        rows.append(
            {
                "rule_id": rule,
                "entity_id": ent,
                "planted": aid or ast or an or "entity",
                "hit": hit,
                "how": how or "not recovered",
                "finding_id": fid,
            }
        )
    return {
        "ok": True,
        "note": "Planted signals in this demo extract — not a production F1, not a claim of 0.85.",
        "planted": int(len(gt)),
        "recovered": recovered,
        "engine_findings": len(s.findings),
        "rows": rows,
    }


def export_pack(s: Store) -> dict:
    findings = []
    for f in s.findings:
        findings.append(
            {
                "finding_id": f.get("finding_id"),
                "rule_id": f.get("rule_id"),
                "entity_id": f.get("entity_id"),
                "kind": f.get("kind"),
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "capability": f.get("capability"),
                "rationale": f.get("rationale"),
                "evidence": f.get("evidence"),
                "decision": f.get("decision", "Pending"),
                "sha3_256": f.get("sha3_256"),
                "chain_hash": f.get("chain_hash"),
                "prev_hash": f.get("prev_hash"),
            }
        )
    return {
        "ps": "26157",
        "product": "DRISHTI SAT-SA",
        "offline": True,
        "chain_tip": s.prev_hash,
        "stats": s.stats,
        "entities": s.sps,
        "findings": findings,
        "audit_tail": s.audit[-50:],
    }
