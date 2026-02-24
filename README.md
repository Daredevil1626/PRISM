<p align="center">
  <img src="docs/prism-cover.png" alt="PRISM Cover" width="900"/>
</p>

<h1 align="center">PRISM</h1>

<p align="center">
  <b>Enhanced Software Transparency · Reverse Engineering · Green Computing Intelligence</b>
</p>

<p align="center">
  A unified instrument for understanding software trust — structurally, behaviorally, and environmentally.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-desktop-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/gui-tkinter-success?style=flat-square"/>
  <img src="https://img.shields.io/badge/domain-reverse%20engineering-purple?style=flat-square"/>
  <img src="https://img.shields.io/badge/green-computing-brightgreen?style=flat-square"/>
</p>

<p align="center">
  <i>Genesys 2.0 Hackathon · GRONIT CO₂ Green Computing Challenge</i>
</p>

---

## Overview

**PRISM** is an advanced desktop analysis system designed to make software **legible, explainable, and measurable**.

Rather than relying on opaque verdicts or signature-only detection, PRISM combines static analysis, lightweight reverse engineering, runtime observation, and environmental impact modeling into a **single, cohesive platform**.

PRISM does **not execute untrusted code**.  
It observes, infers, correlates, and scores.

---

## Design Philosophy

PRISM is built around four non-negotiable principles:

- **Transparency over verdicts**
- **Explainability over black-box scoring**
- **Context over raw indicators**
- **Sustainability as a first-class metric**

No individual heuristic can dominate the system.  
Every score is bounded, weighted, and traceable.

---

## System Architecture

PRISM is composed of loosely coupled analytical engines:

1. Static Transparency Engine  
2. Reverse Engineering Engine  
3. Process & Resource Observer  
4. Energy & Sustainability Analyzer  
5. Trust & Scoring Orchestrator  

Each engine produces independent signals which are synthesized into a final trust profile.

---

## Core Capabilities

### Binary Transparency Analysis

- File metadata (size, timestamps)
- Cryptographic hashes (MD5, SHA-256)
- Shannon entropy analysis with qualitative interpretation
- Readable string extraction
- Detection of suspicious indicators:
  - URLs and IP addresses
  - registry references
  - Base64-like encoded payloads
- Heuristic identification of risky API imports

**Purpose:** Measure opacity and surface latent intent.

---

### Binary Format Identification

- Lightweight PE / ELF detection
- Architecture inference
- Header-level structural awareness

**Purpose:** Establish execution context with minimal overhead.

---

### Reverse Engineering (Static & Bounded)

- Custom x86/x64 disassembler
  - intentionally limited opcode coverage for speed and safety
- Instruction sampling (address, opcode, mnemonic, operands)
- Control Flow Graph (CFG) construction:
  - basic block discovery
  - successor / predecessor mapping
  - approximate function identification
- Code pattern statistics:
  - calls, jumps, returns
  - stack operations
  - arithmetic density

**Purpose:** Understand structural complexity without full emulation.

---

### Process & Resource Monitoring

- Live CPU, memory, network, and disk I/O graphs
- Always-visible mini system dashboard
- High-risk process prioritization
- Parent–child process relationship tracking
- Zombie process detection (explicitly marked safe)
- Orphan process detection with false-positive suppression

High resource usage alone is **never** treated as malicious behavior.

---

### Energy & Green Computing Intelligence

PRISM treats **energy consumption as a security-relevant signal**.

Features include:

- Device profiling (OS, model, battery state)
- Heuristic idle power baseline estimation
- CPU-TDP-based power modeling
- Real-time power (W) and energy (J / Wh) estimation
- CO₂ impact calculation using **0.82 g CO₂ / Wh**
- Energy efficiency and sustainability scoring
- Theoretical clean-system comparison with savings projection

**Purpose:** Quantify the environmental cost of software behavior.

---

### Trust & Scoring System

PRISM produces a **multi-dimensional trust profile**, not a binary label.

Scores include:

- Transparency
- Security
- Efficiency
- Sustainability
- Reverse Engineering Quality
- Energy / Green Impact

All scores are weighted, capped, and explainable.

Final output includes:
- overall trust score
- qualitative rating
- human-readable reasoning

---

### Directory Scanner

- Fast triage scan of directories (e.g., Downloads)
- Entropy and keyword-based heuristics
- Early warning for suspicious artifacts

Designed for **signal discovery**, not deep forensic analysis.

---

## User Interface

PRISM provides a multi-tab desktop interface:

- **Overview** — file summary, entropy, CFG metrics
- **Disassembly** — sampled decoded instructions
- **Control Flow** — function and basic block summaries
- **Detailed Analysis** — trust score breakdown and reasoning
- **Process Monitor** — live high-risk processes
- **Directory Scanner** — folder-level inspection
- **Resource Metrics** — CPU / memory / network / disk graphs
- **Energy / Green** — power, efficiency, CO₂ insights

---

## Installation

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install psutil matplotlib numpyLinux Notes

Some Linux distributions do not bundle Tkinter by default.

sudo apt-get install python3-tk
Running PRISM
python Prism.py

The application launches as a desktop GUI with multiple analytical tabs.

Reports & Data Export

PRISM supports structured data export for downstream analysis and auditing.

Full Analysis Export (JSON)
Complete snapshot of file analysis, runtime metrics, energy data, and trust scores.

Raw Metrics Export
Low-level analysis data suitable for research, validation, or external tooling.

All exports are designed for reproducibility, traceability, and auditability.

Design Boundaries & Limitations

PRISM intentionally prioritizes safety, explainability, and performance over exhaustive depth.

Known constraints include:

Disassembly covers a limited opcode subset

CFG and function detection are approximate

Energy and CO₂ values are heuristic estimates, not sensor readings

Import detection is string-based

Packed or encrypted samples may evade deep inspection

These are deliberate engineering trade-offs, not oversights.

Ethics & Responsible Use

PRISM is a heuristic transparency tool, not a definitive authority.

False positives and false negatives are possible

Results should not be treated as final malware verdicts

Always validate findings with professional security tooling

Use responsibly and in compliance with local laws and ethical standards

Roadmap

Planned and exploratory enhancements include:

Expanded opcode and instruction coverage

Visual Control Flow Graph (CFG) rendering

Plugin-based detection framework (YARA, signature engines)

Deeper PE / ELF parsing (imports, exports, sections)

Cross-platform packaging (PyInstaller)

Closing Note

PRISM is not an antivirus.
It is not a sandbox.

It is an instrument — built to make software behavior legible,
its structure inspectable,
and its cost measurable.
