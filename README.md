# 🛡️ Project SHADOW-INTEL (SIH26189)
### *Next-Generation AI-Powered Criminal Network Analysis & Law Enforcement Intelligence Platform*

[![Smart India Hackathon](https://img.shields.io/badge/SIH-2026-orange.svg?style=for-the-badge)](https://sih.gov.in)
[![Ministry](https://img.shields.io/badge/Ministry-Home%20Affairs%20(MHA)-blue.svg?style=for-the-badge)](https://www.mha.gov.in)
[![Problem ID](https://img.shields.io/badge/Problem%20ID-SIH26189-red.svg?style=for-the-badge)](#)
[![Theme](https://img.shields.io/badge/Theme-Blockchain%20%26%20Cybersecurity-green.svg?style=for-the-badge)](#)
[![Legal Compliance](https://img.shields.io/badge/Legal%20Compliance-BSA%202023%20%7C%20Sec%2065B-purple.svg?style=for-the-badge)](#)
[![Architecture](https://img.shields.io/badge/Architecture-Two--Graph%20Model%20%26%20Zero--LLM%20Core-cyan.svg?style=for-the-badge)](#)

---

## 📌 Executive Summary & Problem Overview

* **Problem Statement ID:** `SIH26189`
* **Title:** **AI-Powered Criminal Network Analysis System**
* **Organization:** **Ministry of Home Affairs (MHA)** *(Supported by BPR&D / NCRB / I4C / NIA)*
* **Category:** Software / Cybersecurity / Defense Intelligence

### The Real-World Challenge:
Modern criminal syndicates—including cyber fraud rings, interstate extortion gangs, drug cartels, and cross-border networks—operate in heavily insulated layers. Investigating Officers (IOs) in Indian Law Enforcement Agencies (LEAs) face fragmented, multi-source data dumps:
* **Telecom CDRs, IPDRs & Tower Dumps** (Airtel, Jio, Vi, BSNL)
* **Multilingual CCTNS FIRs** (Hindi, Marathi, Tamil, Bengali, English)
* **1930 Cyber Fraud & Bank Statements** (Layered UPI VPAs and Bank Accounts)
* **Physical Sightings & Vehicle Logs** (ANPR Plates & FASTag checkpoints)
* **Satellite Communications** (Thuraya, Iridium gateway intercepts)

**Project SHADOW-INTEL** solves this through a unified **Two-Graph Architecture**: combining a high-performance **Knowledge Graph (Neo4j)** for de-anonymizing criminal networks with an **Execution Graph (Task DAG)** for parallel ingestion, backed by an immutable **Blockchain Evidence Locker** strictly compliant with the **Bharatiya Sakshya Adhiniyam (BSA 2023)** and **Section 65B**.

---

## 🏛️ System Architecture: The Two-Graph Model

The platform cleanly separates the **Investigation Reality** from the **Computation Workflow**:

```text
                           SHADOW-INTEL PLATFORM
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           ▼                                                   ▼
 ┌───────────────────┐                               ┌───────────────────┐
 │ INVESTIGATION API │                               │  EXECUTION PLANE  │
 │   (FastAPI REST)  │                               │ (Task DAG Engine) │
 └─────────┬─────────┘                               └─────────┬─────────┘
           │                                                   │
           ▼                                                   ▼
 ┌───────────────────┐                               ┌───────────────────┐
 │  INVESTIGATOR UI  │                               │ PARALLEL WORKERS  │
 │(React + Cytoscape)│                               │ (CDR, FIR, Banks) │
 └───────────────────┘                               └─────────┬─────────┘
                                                               │
                                                               ▼
                                                     ┌───────────────────┐
                                                     │ EVIDENCE CONTRACT │
                                                     │(Source+Provenance)│
                                                     └─────────┬─────────┘
                                                               │
                                                               ▼
                                                     ┌───────────────────┐
                                                     │  KNOWLEDGE PLANE  │
                                                     │  (Neo4j Graph DB) │
                                                     └─────────┬─────────┘
                                                               │
                                  ┌────────────────────────────┼────────────────────────────┐
                                  ▼                            ▼                            ▼
                          ┌───────────────┐            ┌───────────────┐            ┌───────────────┐
                          │ Centrality/AI │            │  Mule Tracing │            │ Tower Matches │
                          └───────────────┘            └───────────────┘            └───────────────┘
                                  │                            │                            │
                                  └────────────────────────────┼────────────────────────────┘
                                                               ▼
                                                     ┌───────────────────┐
                                                     │   FINAL OUTPUTS   │
                                                     │ Graph•Timeline•Doc│
                                                     └───────────────────┘
```

1. **Knowledge Graph (Neo4j):** Represents what the investigation knows (`Suspect`, `Phone`, `Device`, `Account`, `CellTower`, `FIRCase`) and their multi-hop relationships (`CALLED`, `TRANSFERRED_TO`, `INSERTED_IN`, `CO_LOCATED_WITH`).
2. **Execution Graph (Task DAG):** Orchestrates asynchronous source ingestion, dependency resolution, parallel worker fan-out, and evidence fusion.

---

## 🔒 Defense-Grade Security & Blockchain Evidence Locker

To guarantee that no outside hacker, corrupt insider, or defense challenge can compromise the investigation, SHADOW-INTEL integrates a **Dual-Tier Blockchain Security Model**:

```text
[ Ingested Raw Evidence (CDR / FIR / Bank CSV) ]
                        │
                        ▼
         [ SHA-256 / Keccak-256 Hash ]
                        │
                        ▼
         [ Smart Contract: EvidenceLocker.sol ]
                        │
         ├── 1. Immutable Block Timestamp & Merkle Root
         ├── 2. Investigating Officer PKI Digital Signature
         └── 3. Automated BSA 2023 / Sec 65B Digital Certificate
```

* **Mathematical Tamper Detection:** If any database record or file is modified after ingestion, the live hash mismatches the on-chain hash, immediately raising a critical tampering alert.
* **Immutable Audit Trail (`AuditTrail.sol`):** Every officer search, filter, and dossier export is permanently committed to the blockchain, eliminating repudiation.
* **Courtroom Public Verification:** Judges, prosecutors, and defense attorneys can verify the authenticity of exported investigation dossiers via an embedded QR code linking to on-chain proofs.

---

## 🚀 The 6 Core Intelligence Engines

### 1. 👑 Insulated Kingpin & Centrality Engine
* **Betweenness & PageRank:** Discovers top-level syndicate handlers who avoid direct contact with victims but act as critical communication bridges.
* **Louvain Community Detection:** Partitions massive graphs into functional cells (Mule Ring, Hawala, Enforcers, Logistics).

### 2. 📞 Telecom & Geo-Temporal Engine
* **IMEI-IMSI Swapping Resolver:** Bipartite graph mapping that aggregates 10+ discarded burner SIMs sharing a physical device into a single target.
* **Tower Dump Intersection:** Deterministic boolean filtering across crime scene geofences to isolate perpetrator devices from thousands of bystanders.
* **Satellite Phone Correlation:** Ingests Thuraya/Iridium gateway intercepts and correlates satellite GPS fixes with terrestrial GSM movements.

### 3. 💳 Cyber Financial Fraud & Mule Ring Tracer (I4C / 1930)
* **Multi-Hop Layering:** Traces stolen cyber fraud funds fanning out through primary, secondary, and cashout mule accounts within minutes.
* **Smurfing Detection:** Flags micro-transactions structured to remain below banking AML reporting limits (e.g., ₹49,000).
* **Crypto-Fiat Bridges:** Traces off-ramping into USDT (TRC-20) and Bitcoin illicit wallets.

### 4. 📄 Multilingual Indic Police NLP (CCTNS / ICJS)
* **Bhashini & IndicBERT NER:** Extracts suspect names, aliases, BNS/IPC sections, weapons, and vehicle plates from regional FIRs.
* **Modus Operandi (MO) Matcher:** Dense vector embeddings match new crime patterns against historical unsolved cases nationwide.

### 5. ⛓️ Blockchain Evidence Locker & BSA 2023 Compliance
* **Cryptographic Ingestion Locks:** SHA-256 hash committed to EVM smart contracts.
* **Automated Section 65B Certificate:** Generates statutory electronic evidence affidavits with machine parameters and officer digital signatures.

### 6. 🧠 Explainable AI (XAI) Investigator Copilot
* **Zero-Hallucination GraphRAG:** Translates natural language queries into deterministic Neo4j Cypher queries.
* **4-Tier Evidence Classification:** Every relationship is explicitly tagged as `OBSERVED`, `DERIVED`, `INFERRED`, or `GENERATED`.

---

## 🌿 Git Branching Strategy & Architecture

```text
main (Production / Live Evaluation Branch)
  │
  └── develop (Central Integration & Testing)
        │
        ├── feature/execution-core-contract   # Task DAG, Evidence Schema, State
        ├── feature/blockchain-evidence-locker # Solidity Contracts, BSA 2023, Hashing
        ├── feature/telecom-cdr-analytics     # CDR, Tower Dumps, IMEI Swapping
        ├── feature/financial-mule-tracer     # UPI Layering, Bank Forensics, Crypto
        ├── feature/nlp-fir-intelligence      # Multilingual FIRs, Bhashini NLP
        ├── feature/graph-knowledge-engine    # Neo4j Graph, Centrality, Kingpin AI
        └── feature/frontend-dashboard        # React UI, Cytoscape, Timeline, Copilot
```

---

## 🛠️ Technology Stack

| Layer | Technologies |
|---|---|
| **Frontend UI / UX** | React 19, TypeScript, Vite, TailwindCSS, Cytoscape.js, Leaflet (GIS) |
| **Backend & API** | Python 3.10+, FastAPI (Async REST), Pydantic v2 |
| **Knowledge Graph** | Neo4j 5.x (Community / Enterprise), Cypher Query Language |
| **Analytics & Ingestion** | NetworkX, Polars (High-speed CDR processing), Scikit-Learn |
| **NLP & Semantics** | spaCy, IndicBERT / Bhashini API, HuggingFace Transformers |
| **Security & Blockchain** | Solidity, Web3.py, PyCryptodome, SHA-256 Merkle Proofs |
| **DevOps & Containers** | Docker, Docker Compose |

---

## 🚦 Getting Started

### Prerequisites
* **Python** >= 3.10
* **Node.js** >= 18.x
* **Docker & Docker Compose**

### 1. Clone & Setup
```bash
git clone https://github.com/moulishvarmajv/sih-26.git
cd sih-26
```

### 2. Launch via Docker Compose
```bash
docker-compose up --build -d
```
* **Investigator Command Center:** `http://localhost:5173`
* **FastAPI Backend Documentation:** `http://localhost:8000/docs`
* **Neo4j Graph Database Browser:** `http://localhost:7474`

---

## 🏆 Smart India Hackathon Winning Edge

1. **Deterministic Resilience:** Zero reliance on fragile external LLM APIs for core crime-solving logic.
2. **True Indian LEA Grounding:** Real Airtel/Jio CDR headers, CCTNS BNS sections, 1930 portal formats, and Indic language support.
3. **Court-Ready Forensics:** Digital evidence is 100% admissible under the Bharatiya Sakshya Adhiniyam (BSA 2023).
4. **Intuitive Operational Cockpit:** Sub-second multi-hop graph queries with chronological timeline replay.

---
*Developed for the Ministry of Home Affairs (MHA) | Smart India Hackathon 2026 | Problem Statement SIH26189*
