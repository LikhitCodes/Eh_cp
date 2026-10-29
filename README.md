# 🛡️ Sentinel API Shield

**AI-Powered Zombie API Detection & Lifecycle Security Platform for Indian Banks**

> Built for [PSBs Hackathon Series 2026 — iDEA 2.0](https://idea.uba.co.in/) | Problem Statement 9 | Team TITANS

---

## The Problem

Indian banks operate thousands of APIs across core banking, UPI, mobile banking, and third-party integrations. **30–40% of enterprise APIs are undocumented or orphaned** (Salt Security, 2024). These **zombie APIs** — endpoints that should be decommissioned but still handle live financial data — create a critical attack surface with zero authentication, zero encryption, and zero oversight. Each undetected zombie carries **₹5L+ in RBI penalty risk** under the 2021 amended framework.

## The Solution

Sentinel API Shield connects to **5 data sources already inside a bank**, cross-references them, and automatically identifies shadow, orphaned, and zombie APIs:

- An API found via **network scan** but missing from the **API gateway** → **Shadow API**
- An API with **SIEM threat alerts** but no **authentication** → **Zombie API**
- An API whose **spec was removed** from GitHub but still receives **live traffic** → **Undead endpoint**

Each API is scored across **7 weighted risk factors**, classified into **4 lifecycle states**, and remediated through a **dual-approval workflow** with blast radius simulation and automatic rollback.

---

## Architecture

```
Data Sources → Correlation Engine → Risk Scorer → AI Analysis → Policy Engine → Dashboard
(5 connectors)   (dedup + cross-ref)  (7 factors)   (Ollama LLM)  (dual-approval)  (10 pages)
```

**6 Layers** | **26 Components** | **43 API Routes** | **20 Database Models** | **28 Automated Tests**

### Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, FastAPI, SQLAlchemy, Alembic |
| Database | PostgreSQL (prod), SQLite (dev) |
| AI | Ollama LLM (on-premise) with deterministic fallback |
| Frontend | Vanilla JS SPA, Chart.js, Glassmorphism CSS |
| Deployment | Docker (multi-stage), GitHub Actions CI/CD |
| Security | JWT/Keycloak, RBAC (4 roles), SHA-256 audit chain |
| Real-Time | WebSocket streaming, Slack/Teams/PagerDuty webhooks |

---

## Key Features

### Discovery
- **5 Connectors**: Kong Gateway, GitHub Enterprise, Splunk SIEM, Network Scanner, Kubernetes Scanner
- **Cross-source correlation** catches what single tools miss
- **Simulated fallback mode** for demo without real infrastructure

### Risk Assessment
- **7-Factor Scoring**: Exposure (0.20), Auth (0.20), Sensitivity (0.15), Encryption (0.15), Rate Limiting (0.10), Lifecycle (0.10), Threats (0.10)
- **4 Lifecycle States**: Active, Deprecated, Orphaned, Zombie
- **Severity Bands**: Low (0-39), Medium (40-69), High (70-84), Critical (85-100)

### Remediation
- **Dual-approval workflow**: Request, Simulate, Approve, Execute, Verify
- **Blast radius simulation**: Estimates active sessions, affected accounts, daily transactions
- **Automatic rollback** on verification failure
- **Webhook alerting** to Slack, Teams, PagerDuty

### Governance and Compliance
- **6 governance rule types** mapped to RBI 2023 Cybersecurity Framework
- **Continuous compliance scoring** per endpoint
- **SHA-256 cryptographic audit trail** (tamper-evident, SOC 2 ready)
- **Board-ready reports** with ROI in INR (direct loss + regulatory fines + reputation damage)

### AI Analysis
- **On-premise Ollama LLM** — no data leaves the bank
- **Deterministic fallback** when AI unavailable
- **Auto-generated** case summaries and remediation playbooks

---

## Quick Start

### Using Docker (Recommended)

```bash
docker compose up
```

App runs at `http://localhost:8899` with PostgreSQL and optional Ollama AI.

### Local Development

```bash
pip install -r requirements.txt
python serve.py
```

Open `http://localhost:8899/demo`

### Run Tests

```bash
pytest tests/ -v
```

All **28 tests** pass.

---

## Performance

| Metric | Value |
|--------|-------|
| DB Read Latency | 0.38ms |
| Risk Computation | 0.036ms per endpoint |
| Read Throughput | 2,645 endpoints/sec |
| Risk Throughput | 10,000+ assessments/sec |
| Max Capacity | 100,000+ endpoints (PostgreSQL) |
| Test Suite | 28/28 passing |

---

## Project Structure

```
app/
  api/routes.py           # 43 API routes
  models.py               # 20 SQLAlchemy models
  schemas.py              # Pydantic schemas
  main.py                 # FastAPI app
  security.py             # JWT + RBAC
  services/
    ai.py                 # Ollama LLM + fallback
    alerting.py           # Webhook alerting
    connectors.py         # 5 connector implementations
    governance.py         # Compliance engine
    remediation.py        # Blast radius + rollback
    reporting.py          # Reports + ROI model
    risk.py               # 7-factor risk scoring
  static/
    index.html            # SPA shell
    app.js                # 10-page SPA + auto-demo
tests/
  test_api.py             # 16 unit tests
  test_integration.py     # 12 integration tests
Dockerfile                # Multi-stage build
docker-compose.yml        # App + PostgreSQL + Ollama
.github/workflows/ci.yml  # CI/CD pipeline
alembic/                  # Database migrations
serve.py                  # Dev server entry point
```

---

## Regulatory Alignment

| RBI Requirement | Sentinel Feature |
|----------------|-----------------|
| API Inventory Management | 5-connector auto-discovery |
| Lifecycle Governance | 4-state classification |
| Change Management | Dual-approval remediation |
| Audit Trail | SHA-256 cryptographic chain |
| Data Sovereignty | On-premise AI, zero cloud |
| Continuous Monitoring | Scheduled scans, WebSocket alerts |

---

## Team

**Team TITANS** — PSBs Hackathon Series 2026, iDEA 2.0

| Member | Expertise |
|--------|-----------|
| Pulkit Pareek | Full-Stack Development, AI/ML |
| Sudhanshu Mishra | Algorithms |
| Akash Gupta | Entrepreneurship |

---

## License

Built for PSBs Hackathon Series 2026 (iDEA 2.0) organized by Union Bank of India under the Department of Financial Services, Ministry of Finance, Government of India.
