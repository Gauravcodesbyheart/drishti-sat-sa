"""DRISHTI SAT-SA — offline supervisory analytics for NCIIPC (PS 26157)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import csv
import io
import json
import sqlite3
import tempfile
import zipfile

import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from fastapi.responses import FileResponse, JSONResponse, Response

from app.data_gen import generate, DATA_DIR
from app.engine import STORE, export_pack, run_all, top100, validate_planted, weekly_trends
from app.trust import verify

FRONT = ROOT / "frontend"
app = FastAPI(title="DRISHTI SAT-SA", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class DecisionIn(BaseModel):
    finding_id: str
    decision: str
    examiner: str = "supervisor"


PS_USECASES = [
    {"id": "UC-1", "ps": "High-severity alerts closed unusually quickly", "rules": ["EG-01"], "kind": "Execution Gap"},
    {"id": "UC-2", "ps": "Repeated alerts on the same asset without root-cause remediation", "rules": ["EG-04"], "kind": "Execution Gap"},
    {"id": "UC-3", "ps": "Critical alerts closed without appropriate escalation", "rules": ["EG-02", "NS-03"], "kind": "Execution Gap"},
    {"id": "UC-4", "ps": "Critical systems generating little or no security telemetry", "rules": ["NS-01", "EG-05"], "kind": "Negative Space"},
    {"id": "UC-5", "ps": "Significant deviations from peer entities", "rules": ["NS-04"], "kind": "Peer"},
    {"id": "UC-6", "ps": "Missing monitoring coverage for critical environments", "rules": ["NS-08", "NS-02"], "kind": "Negative Space"},
    {"id": "UC-7", "ps": "Repetitive investigation patterns (template / copy-paste)", "rules": ["EG-03"], "kind": "Execution Gap"},
    {"id": "UC-8", "ps": "Behaviours that satisfy metrics without managing cyber risk", "rules": ["EG-06"], "kind": "Execution Gap"},
    {"id": "UC-9", "ps": "Investigation / escalation workload inconsistent with activity", "rules": ["EG-12", "NS-05"], "kind": "Execution Gap"},
]


@app.on_event("startup")
def boot():
    if not (Path(DATA_DIR) / "alerts.csv").exists():
        generate(DATA_DIR)
    if not STORE.loaded:
        run_all(DATA_DIR)


@app.api_route("/", methods=["GET", "HEAD"])
@app.api_route("/index.html", methods=["GET", "HEAD"])
def index():
    return FileResponse(FRONT / "index.html", media_type="text/html")


@app.get("/api/health")
def health():
    return {"ok": True, "offline": True, "loaded": STORE.loaded, "name": "DRISHTI SAT-SA"}


@app.get("/api/overview")
def overview():
    if not STORE.loaded:
        raise HTTPException(503, "not loaded")
    bands = {"High": 0, "Medium": 0, "Low": 0}
    for e in STORE.sps:
        bands[e["band"]] = bands.get(e["band"], 0) + 1
    by_rule, sev = {}, {}
    for f in STORE.findings:
        by_rule[f["rule_id"]] = by_rule.get(f["rule_id"], 0) + 1
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    return {
        "stats": STORE.stats,
        "bands": bands,
        "by_rule": by_rule,
        "by_severity": sev,
        "entities": STORE.sps,
        "ps": "26157",
        "org": "NCIIPC / NTRO",
        "team": "CyberNova",
    }


@app.get("/api/entities/{eid}")
def entity(eid: str):
    row = next((e for e in STORE.sps if e["entity_id"] == eid), None)
    if not row:
        raise HTTPException(404, "unknown entity")
    findings = [f for f in STORE.findings if f["entity_id"] == eid]
    return {
        "entity": row,
        "findings": findings[:80],
        "peer": [
            {"entity_id": e["entity_id"], "entity_name": e["entity_name"], "sps": e["sps"]}
            for e in STORE.sps
            if e["sector"] == row["sector"]
        ],
    }


@app.get("/api/queue")
def queue():
    return {"items": top100(STORE), "total_findings": len(STORE.findings)}


@app.get("/api/negspace")
def negspace():
    items = [f for f in STORE.findings if f["kind"] == "Negative Space"]
    grid = []
    if STORE.assets is not None:
        counts = STORE.alerts.groupby("asset_id").size()
        for _, r in STORE.assets.iterrows():
            n = int(counts.get(r["asset_id"], 0))
            grid.append(
                {
                    "asset_id": r["asset_id"],
                    "name": r["name"],
                    "entity_id": r["entity_id"],
                    "sector": r["sector"],
                    "criticality": r["criticality"],
                    "alerts": n,
                    "silent": n == 0 and r["criticality"] in ("Critical", "High"),
                }
            )
    return {"findings": items[:200], "assets": grid}


@app.get("/api/findings/{fid}")
def finding(fid: str):
    f = next((x for x in STORE.findings if x["finding_id"] == fid), None)
    if not f:
        raise HTTPException(404)
    payload = {k: f[k] for k in ("finding_id", "rule_id", "entity_id", "rationale", "confidence")}
    return {"finding": f, "chain_ok": verify(payload, f)}


@app.post("/api/decide")
def decide(body: DecisionIn):
    f = next((x for x in STORE.findings if x["finding_id"] == body.finding_id), None)
    if not f:
        raise HTTPException(404)
    if body.decision not in ("Accept", "Reject", "False Positive"):
        raise HTTPException(400)
    f["decision"] = body.decision
    f["examiner"] = body.examiner
    STORE._log("decision", {"finding_id": body.finding_id, "decision": body.decision, "examiner": body.examiner})
    return {"ok": True}


@app.get("/api/audit")
def audit():
    return {"entries": STORE.audit[-200:], "length": len(STORE.audit)}


@app.get("/api/alerts/{aid}")
def alert_row(aid: str):
    if STORE.alerts is None:
        raise HTTPException(404)
    hit = STORE.alerts[STORE.alerts["alert_id"] == aid]
    if hit.empty:
        raise HTTPException(404, "unknown alert")
    rec = hit.iloc[0].to_dict()
    for k, v in list(rec.items()):
        rec[k] = str(v)
    return {"alert": rec}


WANTED_CSV = ["alerts.csv", "cases.csv", "assets.csv", "analysts.csv", "playbooks.csv", "compliance.csv", "entities.csv"]


def _write_json_tables(payload: dict, dest: Path) -> int:
    found = 0
    for key in ("alerts", "cases", "assets", "analysts", "playbooks", "compliance", "entities"):
        rows = payload.get(key)
        if isinstance(rows, list) and rows:
            pd.DataFrame(rows).to_csv(dest / f"{key}.csv", index=False)
            found += 1
    return found


@app.post("/api/ingest")
async def ingest(file: UploadFile = File(...)):
    """CSV ZIP, JSON pack, or a named canonical CSV. Not a live SIEM tap."""
    raw = await file.read()
    dest = Path(DATA_DIR)
    dest.mkdir(parents=True, exist_ok=True)
    name = (file.filename or "").lower()
    found = 0
    kind = "zip"
    if name.endswith(".json") or (raw[:1] in (b"{", b"[") and not name.endswith(".zip")):
        kind = "json"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise HTTPException(400, "invalid JSON") from exc
        if isinstance(payload, list):
            raise HTTPException(400, "JSON pack must be an object with alerts/cases/assets arrays")
        found = _write_json_tables(payload, dest)
        if found < 3:
            raise HTTPException(400, "JSON must include alerts, cases and assets arrays")
    elif name.endswith(".csv"):
        kind = "csv"
        base = Path(file.filename or "").name
        if base not in WANTED_CSV:
            raise HTTPException(400, "CSV must be named alerts.csv, cases.csv or assets.csv")
        (dest / base).write_bytes(raw)
        found = 1
        missing = [x for x in ("alerts.csv", "cases.csv", "assets.csv") if not (dest / x).exists()]
        if missing:
            return {"ok": True, "files": found, "pending": True, "need": missing, "kind": kind}
    else:
        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
        except zipfile.BadZipFile as exc:
            raise HTTPException(400, "upload a ZIP of CSVs, a JSON pack, or a named canonical CSV") from exc
        for n in zf.namelist():
            base = Path(n).name
            if base in WANTED_CSV:
                (dest / base).write_bytes(zf.read(n))
                found += 1
        if found < 3:
            raise HTTPException(400, "ZIP must contain alerts.csv, cases.csv, assets.csv")
    run_all(DATA_DIR)
    return {"ok": True, "files": found, "kind": kind, "stats": STORE.stats}


@app.get("/api/trends")
def trends():
    if not STORE.loaded:
        raise HTTPException(503, "not loaded")
    return weekly_trends(STORE)


@app.get("/api/validate")
def validate():
    if not STORE.loaded:
        raise HTTPException(503, "not loaded")
    return validate_planted(STORE, DATA_DIR)


@app.get("/api/export.json")
def export_json():
    if not STORE.loaded:
        raise HTTPException(503, "not loaded")
    body = json.dumps(export_pack(STORE), default=str).encode("utf-8")
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=drishti-sat-sa-pack.json"},
    )


@app.get("/api/export.csv")
def export_csv():
    if not STORE.loaded:
        raise HTTPException(503, "not loaded")
    buf = io.StringIO()
    cols = [
        "finding_id",
        "rule_id",
        "entity_id",
        "kind",
        "severity",
        "confidence",
        "capability",
        "rationale",
        "evidence",
        "decision",
        "sha3_256",
        "chain_hash",
    ]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for f in export_pack(STORE)["findings"]:
        row = dict(f)
        row["evidence"] = "|".join(str(x) for x in (f.get("evidence") or []))
        w.writerow(row)
    return Response(
        content=buf.getvalue().encode("utf-8"),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=drishti-sat-sa-findings.csv"},
    )


@app.get("/api/usecases")
def usecases():
    """PS §4 illustrative use cases mapped to live detector counts."""
    counts = {}
    for f in STORE.findings:
        counts[f["rule_id"]] = counts.get(f["rule_id"], 0) + 1
    out = []
    for u in PS_USECASES:
        n = sum(counts.get(r, 0) for r in u["rules"])
        out.append({**u, "findings": n})
    return {"items": out, "note": "Illustrative PS use cases. Extra detectors beyond this list also fire."}


@app.get("/api/method")
def method():
    return {
        "ps": "26157",
        "offline": True,
        "not": ["SOC", "SIEM", "real-time", "cloud AI", "live log tap"],
        "ml": {
            "architecture": "sklearn IsolationForest (n_estimators=200, contamination=0.15) + TfidfVectorizer cosine > 0.95",
            "hardware": "4 vCPU · 16 GB RAM · 100 GB SSD · no GPU",
            "training": "Fit on the current extract only. No internet. No hosted model.",
            "update": "USB JSON/CSV/ZIP re-ingest. Re-run engine locally.",
            "explainability": "Rules fire first. ML is an extra flag. Trinity: Rationale · Evidence · Confidence.",
            "auditability": "SHA3-256 hash chain. HMAC seal. ML-DSA-65 reserved slot.",
        },
        "ingest": ["CSV ZIP", "JSON pack", "named canonical CSVs"],
        "exports": ["JSON sealed pack", "CSV findings", "SQLite snapshot"],
    }


@app.get("/api/cases/{cid}")
def case_row(cid: str):
    if STORE.cases is None:
        raise HTTPException(404)
    hit = STORE.cases[STORE.cases["case_id"].astype(str) == str(cid)]
    if hit.empty:
        raise HTTPException(404, "unknown case")
    rec = hit.iloc[0].to_dict()
    for k, v in list(rec.items()):
        rec[k] = str(v)
    return {"case": rec}


@app.get("/api/export.sqlite")
def export_sqlite():
    if not STORE.loaded:
        raise HTTPException(503, "not loaded")
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.close()
    con = sqlite3.connect(tmp.name)

    def _sql_ready(df: pd.DataFrame) -> pd.DataFrame:
        out = df.copy()
        for c in out.columns:
            if out[c].dtype == object:
                out[c] = out[c].map(lambda v: json.dumps(v, default=str) if isinstance(v, (dict, list)) else v)
        return out

    if STORE.alerts is not None:
        _sql_ready(STORE.alerts).to_sql("alerts", con, if_exists="replace", index=False)
    if STORE.cases is not None:
        _sql_ready(STORE.cases).to_sql("cases", con, if_exists="replace", index=False)
    if STORE.assets is not None:
        _sql_ready(STORE.assets).to_sql("assets", con, if_exists="replace", index=False)
    _sql_ready(pd.DataFrame(STORE.sps)).to_sql("entities_sps", con, if_exists="replace", index=False)
    pack = export_pack(STORE)
    _sql_ready(pd.DataFrame(pack["findings"])).to_sql("findings", con, if_exists="replace", index=False)
    con.close()
    return FileResponse(
        tmp.name,
        media_type="application/vnd.sqlite3",
        filename="drishti-sat-sa.sqlite",
    )


app.mount("/static", StaticFiles(directory=str(FRONT)), name="static")
