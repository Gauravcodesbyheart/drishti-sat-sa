# DRISHTI SAT-SA — setup (PS 26157)

**Supervisory Analytics Tool for SOC Assessment** · Team **CyberNova2026** · SIH 2026  
NCIIPC / NTRO · Theme: Blockchain & Cybersecurity · Software

> We do not replace the supervisor. The tool says **WORTH CHECKING**, never **GUILTY**.  
> SHA3-256 is **live**. ML-DSA-65 is **next** (slot, not shipping).

This README is only **how to install and run**. Architecture: `ARCHITECTURE.md` / `ARCHITECTURE.pdf`.  
Beginner book: `DRISHTI-SAT-SA-Complete-Documentation.pdf`.

---

## 1. What you need

| Item | Notes |
|------|--------|
| Python **3.10 or 3.11** | From https://www.python.org — Windows: tick **Add Python to PATH** |
| This folder | `app/`, `frontend/`, `requirements.txt` |
| 4 GB RAM free | Demo is CPU-only. **No GPU.** |

Optional: [Docker](https://docs.docker.com/get-docker/) for the air-gap run.

---

## 2. Run on a laptop (recommended SIH demo)

Open a terminal **inside this project folder**.

**macOS / Linux / WSL**

```bash
python3 -m pip install -r requirements.txt
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Windows** (if `python3` is not found, use `py`)

```bat
py -m pip install -r requirements.txt
py -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Leave that window open. In a browser open:

**http://127.0.0.1:8000**

First boot (~5 s) writes a **synthetic** extract (12 CSEs · 3,378 alerts) and runs the engine.

---

## 3. What you should see

Sidebar: Dashboard · Entity Radar · Peer bench · Review Queue · Negative Space · Trends · PS use cases · Workflow · Trust & Audit · Validate · Advisory.

| If this happens | Do this |
|-----------------|--------|
| `No module named uvicorn` | Run the `pip install -r requirements.txt` line again |
| Port 8000 already in use | Add `--port 8001` and open http://127.0.0.1:8001 |
| Blank white page | Hard refresh: Ctrl+F5 (Windows) or Cmd+Shift+R (Mac) |
| Ingest failed | ZIP must contain `alerts.csv`, `cases.csv`, `assets.csv` |

---

## 4. Docker (air-gap style)

Needs Docker Desktop / engine. For a **normal** build (uses network once to pull Python packages):

```bash
docker build -t drishti-sat-sa:offline .
docker run --network=none -p 8000:8000 drishti-sat-sa:offline
```

`--network=none` = the **running** container cannot call the internet.

A fully offline **build** also needs wheels pre-downloaded into `./wheels`. For the hackathon laptop, section 2 is enough.

---

## 5. What this product is (and is not)

**Is:** offline supervisory analytics **after** the CSE SIEM. USB ZIP / JSON / CSV in. Examiner Accept / Reject / FP.

**Is not:** a SOC, a SIEM, real-time monitoring, a live Splunk/QRadar tap, a cloud LLM, or an NCIIPC production deployment.

Do not upload **real** CSE extracts to a public GitHub repo. The files in `data/sample/` are synthetic.

---

## 6. Project layout

```
DRISHTI-SAT-SA/
  README.md                 ← you are here (setup)
  ARCHITECTURE.md / .pdf    ← SIH architecture (max 2 pages)
  requirements.txt
  Dockerfile
  app/main.py               FastAPI (pages + /api)
  app/engine.py             12 EG + 8 NS + Isolation Forest + TF-IDF + SPS
  app/data_gen.py           synthetic 12-CSE extract
  app/trust.py              SHA3-256 hash chain (ML-DSA-65 interface)
  frontend/                 dashboard UI (no npm / no CDN)
  data/sample/              demo CSVs after first boot
```

---

## 7. Libraries (`requirements.txt`)

```
fastapi==0.115.6
uvicorn==0.34.0
pandas==2.2.3
numpy==2.2.2
scikit-learn==1.6.1
python-multipart==0.0.20
```

Why these: pandas for CSVs, scikit-learn Isolation Forest + TF-IDF **on CPU**, FastAPI so the UI needs no Node build. No cloud APIs.

---

## 8. SIH portal extras

| Portal field | File / action |
|--------------|----------------|
| Source Code Link | Push this folder to GitHub, paste the repo URL |
| Readme with Setup | this file |
| Architecture (max 2 pages) | `ARCHITECTURE.pdf` (from `ARCHITECTURE.md`) |
| Demo video (max 2 min) | Record http://127.0.0.1:8000 |

```bash
git init
git add .
git commit -m "DRISHTI SAT-SA PS 26157"
git branch -M main
git remote add origin https://github.com/YOUR_USER/drishti-sat-sa.git
git push -u origin main
```

Add a `.gitignore` with `__pycache__/`, `.venv/`, and `data/offline_seal.key`.
