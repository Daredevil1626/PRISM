PRISM

Enhanced Software Transparency, Reverse Engineering & Green Computing Analyzer

A unified instrument for understanding software trust — structurally, behaviorally, and environmentally.

Genesys 2.0 Hackathon
PRISM Project · GRONIT CO₂ Green Computing Challenge

What PRISM Is

PRISM is a research-grade desktop analysis system that brings together:

static binary transparency analysis

lightweight reverse engineering (disassembly + control-flow modeling)

live system & process monitoring

and energy / CO₂ impact estimation

into a single, explainable, GUI-driven tool.

It is designed for situations where:

black-box verdicts are unacceptable

false positives are costly

and sustainability is part of software quality, not an afterthought

PRISM does not execute unknown code.
It observes, measures, and infers.

System Architecture (Conceptual)

PRISM is organized as loosely coupled analytical engines, coordinated by a GUI layer:

Static Transparency Engine

Reverse Engineering Engine

Process & Resource Observer

Energy & Sustainability Analyzer

Trust & Scoring Orchestrator

Each engine produces bounded, explainable outputs.
No single signal can dominate the final result.

Core Capabilities
Binary Transparency Analysis

File metadata: size, timestamps, MD5 / SHA-256

Shannon entropy with qualitative assessment

Readable string extraction

Detection of suspicious patterns:

URLs, IP addresses

registry references

Base64-like encoded payloads

Heuristic detection of risky API imports (string-based)

Purpose:

Measure opacity and surface latent intent.

Binary Format Identification

Lightweight PE / ELF detection

Architecture inference

Header-level structural awareness

Purpose:

Establish execution context without full parsing overhead.

Reverse Engineering (Static, Fast, Bounded)

Custom x86/x64 disassembler

intentionally limited opcode coverage for speed and safety

Instruction sampling (address, opcode, mnemonic, operands)

Control Flow Graph (CFG) construction:

basic block identification

successor / predecessor mapping

approximate function discovery

Code pattern statistics:

calls, jumps, returns

stack operations

arithmetic density

Purpose:

Understand structural complexity without full emulation.

Process Transparency & Resource Monitoring

Live CPU, memory, network, and disk I/O graphs

Process list with risk-weighted ordering

Parent–child relationship reconstruction

Zombie process detection (explicitly marked safe)

Orphan process detection with false-positive suppression

Mini always-visible dashboard for system context

Design principle:

High resource usage ≠ malicious behavior.

Context is mandatory.

Energy & Green Computing Intelligence

PRISM treats energy as a first-class analytical signal.

Includes:

Device profiling (OS, model, battery state)

Heuristic idle baseline estimation

CPU-TDP–based power modeling

Real-time power (W) and energy (J / Wh) estimation

CO₂ impact calculation (0.82 g CO₂ / Wh)

Energy efficiency score

Sustainability insights and comparative “clean baseline” framing

Purpose:

Quantify the environmental cost of software behavior.

Trust & Scoring System

PRISM produces a multi-dimensional trust profile, not a binary label.

Scores include:

Transparency (entropy, obfuscation)

Security (patterns, APIs, strings)

Efficiency (CPU & memory behavior)

Sustainability (network, disk, energy)

Reverse Engineering Quality

Energy / Green Impact

All scores are:

weighted

capped

and explainable

Final output:

overall trust score

qualitative rating

human-readable reasoning

Directory & File Sweep Mode

Fast scanning of folders (e.g., Downloads)

Entropy + keyword heuristics

Early warning for suspicious artifacts

Designed as a triage pass, not deep analysis

Reports & Data Export

Full analysis export as JSON

Raw metrics export for external research

Designed for:

reproducibility

auditability

downstream processing

Technology Stack

Language: Python 3.8+

GUI: tkinter

System Metrics: psutil

Math & Visualization: numpy, matplotlib

Core Utilities: hashlib, struct, platform, subprocess, pathlib

tkinter ships with most Python builds.
Some Linux distributions require python3-tk.

Installation
# Recommended: virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install psutil matplotlib numpy

Linux (if Tk is missing):

sudo apt-get install python3-tk
Running PRISM
python Prism.py

The GUI launches with multiple analytical tabs:

Overview — file summary, entropy, CFG metrics, crypto indicators

Disassembly — sampled decoded instructions

Control Flow — function & basic-block summaries

Detailed Analysis — trust score breakdown and reasoning

Process Monitor — live high-risk processes

Directory Scanner — fast suspicious file sweep

Resource Metrics — CPU / memory / network / disk graphs

Energy / Green — power, efficiency, CO₂ insights

How PRISM Works (Condensed Flow)

Static Read
File bytes are read safely; hashes and entropy computed.

Structural Inference
Format detection, disassembly, and CFG synthesis.

Behavioral Context
Live system metrics and process relationships observed.

Energy Modeling
Power and CO₂ estimated relative to a clean baseline.

Trust Synthesis
Weighted, explainable scoring across all dimensions.

Design Boundaries & Limitations

Disassembly covers a limited opcode subset

CFG and function detection are approximate

Energy estimates are heuristic, not sensor-grade

Import detection is string-based

Packed / encrypted samples may evade deep inspection

These constraints are intentional trade-offs for safety, speed, and clarity.

Ethics & Responsible Use

PRISM is a heuristic transparency tool.

It may produce false positives or negatives

It should not be the sole authority for malware labeling

Always validate findings with professional tooling

Use responsibly and within legal boundaries

Roadmap (Indicative)

Expanded opcode coverage

Visual CFG rendering

Plugin system (YARA, signature engines)

Deeper PE / ELF parsing

Cross-platform packaging (PyInstaller)

Final Note

PRISM is not an antivirus.
It is not a sandbox.

It is an instrument — built to make software behavior legible,
its structure inspectable,
and its cost measurable.
