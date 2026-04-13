# Mewtwo

Mewtwo is a personal AI-assisted toolkit that acts as a sidekick throughout the entire bug bounty workflow — from recon to report. It bridges a purple team background with BB-specific methodology: thinking like an attacker to surface attack surface, while documenting like a defender to produce clean, professional reports.

---

## Overview

Mewtwo automates and augments the repetitive stages of bug bounty hunting by combining offensive recon techniques with structured, report-ready output. Whether you're enumerating subdomains, probing for vulnerabilities, or drafting a submission, Mewtwo keeps the context and reduces cognitive overhead.

---

## Features

- **Recon automation** — subdomain enumeration, port scanning, fingerprinting, and asset discovery
- **Attack surface mapping** — identifies exposed endpoints, parameters, and technologies worth investigating
- **Vulnerability triage** — correlates findings against known patterns and prioritizes by severity
- **AI-assisted analysis** — applies purple team thinking to surface non-obvious attack paths
- **Report generation** — produces structured, professional bug bounty reports ready for submission
- **Workflow continuity** — maintains context across recon, exploitation, and documentation phases

---

## Workflow

```
Target Scope
    │
    ▼
Recon & Enumeration
    │  - Subdomain discovery
    │  - Port & service scanning
    │  - Technology fingerprinting
    ▼
Attack Surface Analysis
    │  - Endpoint mapping
    │  - Parameter discovery
    │  - Auth surface review
    ▼
Vulnerability Investigation
    │  - Pattern matching
    │  - Manual + AI-assisted probing
    ▼
Report Generation
       - Structured write-up
       - PoC documentation
       - Severity classification
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- API keys configured (see Configuration section)

### Installation

```bash
git clone https://github.com/mithunsreeram/mewtwo.git
cd mewtwo
pip install -r requirements.txt
```

### Configuration

Copy the example config and fill in your credentials:

```bash
cp config.example.yaml config.yaml
```

---

## Usage

```bash
# Run full recon pipeline on a target
python mewtwo.py recon --target example.com

# Generate a report from collected findings
python mewtwo.py report --findings findings.json

# Interactive mode
python mewtwo.py shell
```

---

## Philosophy

Mewtwo is built around the idea that the best bug bounty hunters think like both attackers and defenders simultaneously. The tooling reflects that: every recon decision is made with an eye toward what a defender would miss, and every report is structured the way a security team would want to receive it.

---

## License

Personal use. Not intended for unauthorized testing. Always operate within authorized scope.
