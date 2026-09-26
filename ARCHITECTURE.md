# DRISHTI SAT-SA — Architecture (PS 26157)

**Team CyberNova · SIH 2026 · Offline explainable supervisory analytics for NCIIPC**  
**One line:** DRISHTI sits *after* the CSE SIEM. SHA3-256 is live. ML-DSA-65 is next. Engine never closes a ticket.

## 1. Purpose and boundary

NCIIPC already receives SOC *output*. SAT-SA judges whether that output is *work*. DRISHTI does not monitor live, collect telemetry, or replace Splunk / QRadar / Sentinel. Examiners Accept / Reject / FP every queued finding.

**Offline contract:** no internet, no cloud, no SaaS, no hosted models. USB ZIP / JSON / CSV in → dashboard + sealed JSON/CSV/SQLite out.

**Out of scope:** CSE SOC, real-time, SIEM, multi-tenant SOC, national sensor grid, continuous log collection.

## 2. Six layers

```
CSE extract (USB ZIP / JSON / CSVs)
  → Canonical store (pandas, DuckDB-ready + SHA3 of each file)
    → Dual engine (12 execution-gap + 8 negative-space + Isolation Forest + TF-IDF)
      → SPS 0–100 + sector trimmed median + Z>2
        → Top-100 queue (confidence × severity × capability, diversified)
          → Trinity + SHA3-256 chain → Supervisor UI
```

| Layer | What happens |
|-------|----------------|
| Ingest | Schema check, provenance hash, no raw logs / PII |
| Store | Alerts, cases, assets, analysts, playbooks, compliance |
| Detect | Deterministic rules first (auditable); ML only as an extra flag |
| Score | Capability concern rates → SPS; peer by sector |
| Prioritise | 100 rows a person can finish; engine never decides |
| Trust | Rationale, evidence ids, confidence, SHA3-256 (ML-DSA-65 slot) |

**Runtime:** Python 3.11, FastAPI, pandas, scikit-learn. UI = static SPA, relative `/api/*`, no CDN. Hardware: 4 vCPU, 16 GB RAM, 100 GB SSD, **no GPU**. Network: `docker run --network=none`.

## 3. Dual engine (PS §3)

**A. Execution gaps** — evidence contradicts the KPI.

| ID | Signal | Conf |
|----|--------|------|
| EG-01 | Critical ∧ dwell&lt;10 ∧ steps&lt;2 ∧ ¬escalation | 0.90 |
| EG-02 | Critical closed, no escalation | 0.85 |
| EG-03 | TF-IDF cosine&gt;0.95, same analyst | 0.91 |
| EG-04 | Same asset+type ≥5 times, no RCA | 0.80 |
| EG-05 | Critical asset, 0 alerts, peers noisy | 0.93 |
| EG-06 | Fast MTTR + templates + low escalation | 0.88 |
| EG-07 | Critical/High, 0 investigation steps | 0.82 |
| EG-08 | Escalation after SLA | 0.75 |
| EG-09 | Critical notes &lt;20 chars | 0.70 |
| EG-10 | Malware closed without evidence | 0.80 |
| EG-11 | Dwell exceeds severity SLA | 0.75 |
| EG-12 | Analyst load &gt;3× team median | 0.65 |

**B. Negative space** — expected evidence is missing.  
NS-01 silent critical asset · NS-02 missing MITRE/category vs sector · NS-03 zero critical escalations · NS-04 volume &lt;10% peer median · NS-05 silent analyst · NS-06 missing control evidence · NS-07 no night/weekend alerts · NS-08 critical-asset coverage gap.

**ML (PS §5):** sklearn IsolationForest, n=200, contamination=0.15, on `(MTTR, escalation_rate, investigation_steps, silent_rate, fast_critical, night_rate)`. Fit on the current extract only. TF-IDF cosine &gt; 0.95 for templates. **Rules fire first.** Update = USB re-ingest.

## 4. SPS, queue, trust, validation

Eight NCIIPC capabilities: Detection 20%, Investigation 20%, Escalation 15%, IR 15%, SecOps 10%, Governance 10%, Discipline 5%, Resilience 5%. **SPS = weighted concern rate; high = more attention.** Sector trimmed median (10% tails), Z&gt;2 peer flag.

Queue score = `confidence × severity_weight × (1+cap_weight) × (1+0.15|z|)` with a per-rule cap so Top 100 is not 100 copies of EG-01.

Every finding: Rule ID, Confidence, Rationale, Evidence, capability, SHA3-256, previous chain hash, HMAC seal. Production swap: HMAC → **ML-DSA-65**. Examiner decisions append to the same chain.

**Demo extract (measured):** 12 CSEs · 3,378 alerts · 235 findings · Top 100. Planted `ground_truth.csv` recovered **38 / 40** on this set. Design target F1&gt;0.85 is for a larger labelled extract — **not** claimed as a result of this demo.
