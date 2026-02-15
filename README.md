
# PRISM — Enhanced Software Transparency Analyzer

A comprehensive desktop tool that combines **binary transparency analysis**, **reverse engineering (disassembly + control‑flow graph)**, **resource monitoring**, and **green computing/energy metrics**—all in a single, user‑friendly **Tkinter GUI**.

> Genesys 2.0 Hackathon — PRISM Project + GRONIT CO2 Green Computing Challenge

---

## ✨ Key Features

- **Load & Analyze Binaries**: File info (hashes, size, timestamps), entropy assessment, strings extraction, suspicious patterns (URLs/IPs/registry/base64), and risky API imports.
- **Binary Format Detection**: Lightweight PE/ELF identification (architecture, sections).
- **Reverse Engineering**:
  - Custom **x86/x64 disassembler** (limited but fast) for sample instruction decoding.
  - **Control Flow Graph (CFG)** construction with basic blocks, successors, and function discovery.
  - Code pattern stats (calls/jumps/returns/stack ops/arithmetic).
- **Resource Monitoring**: Live CPU, memory, network, disk I/O charts; always‑visible mini dashboard.
- **Energy / Green Computing**:
  - Device profile heuristics (OS, model, battery state, baseline idle watts).
  - Real‑time **power estimation** and **energy/CO₂** metrics (J, W, Wh → grams CO₂ via 0.82 g/Wh).
  - **Energy efficiency score** and sustainability impact with practical savings projections.
- **Trust Scores**: Weighted overall score + breakdown (Transparency, Security, Efficiency, Sustainability, RE Quality, Energy/Green).
- **Directory Scanner**: Fast pass to flag suspicious files with entropy & keyword heuristics.
- **Reports & Export**: Save full analysis and metrics as JSON; export raw analysis data.

---

## 🧰 Tech Stack

- **Python 3.8+**
- GUI: `tkinter`
- System/metrics: `psutil`
- Math/plots: `numpy`, `matplotlib`
- Misc: `hashlib`, `struct`, `platform`, `subprocess`, `pathlib`

> Note: `tkinter` comes with most Python distributions. On some Linux distros you may need to install `python3-tk`.

---

## 📦 Installation

```bash
# (Recommended) use a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install required packages
pip install psutil matplotlib numpy
```

On **Linux** you might need:
```bash
sudo apt-get install python3-tk
```

---

## 🚀 Running PRISM

```bash
python Prism.py
```

The app launches a desktop GUI with multiple tabs:
- **Overview** — summary of file info, disassembly counts, CFG metrics, crypto detection.
- **Disassembly** — sample instructions (address/opcode/mnemonic/operands).
- **Control Flow** — functions + basic blocks sample details.
- **Detailed Analysis** — trust score formula and breakdown, findings, and recommendations.
- **Process Monitor** — live high‑risk process list with auto‑refresh.
- **Directory Scanner** — scan a folder (e.g., Downloads) for suspicious files.
- **Resource Metrics** — 2×2 live graphs for CPU/Mem/Net/Disk.
- **Energy/Green** — real‑time power, theoretical clean system comparison, CO₂ banner, insights.

---

## 📝 How It Works (High Level)

1. **Static Analysis**
   - Reads the target file bytes and computes **MD5/SHA‑256**.
   - Extracts readable **strings** and flags suspicious keywords.
   - Computes **Shannon entropy** to infer obfuscation or packing.
   - Heuristically detects dangerous **API imports** embedded in the binary.

2. **Binary Format & RE**
   - Identifies **PE/ELF** and architecture via header parsing.
   - Performs fast **x86/x64 disassembly** (limited opcode table) for the first ~2KB.
   - Builds a **CFG** by detecting leaders, successors, and basic blocks; approximates functions.

3. **Runtime Metrics & Energy**
   - Uses `psutil` for **CPU/memory/network/disk** sampling.
   - Estimates **power** using idle baseline + CPU‑TDP scaling, aggregates **energy (J)**, and converts to **CO₂ (g)** using 0.82 g/Wh.

4. **Trust Scoring**
   - Computes weighted scores for **Transparency, Security, Efficiency, Sustainability, RE Quality, Energy/Green**, and an **Overall rating**.

---

## 📷 Screenshots (placeholders)

Add screenshots to help users navigate the UI:
- `docs/overview.png`
- `docs/disassembly.png`
- `docs/energy.png`

> Create a `docs/` folder and drop images; then update this section.

---

## ⚙️ Configuration & Tuning

- **CPU_TDP_WATTS**: Default `65` W. Tune based on your hardware for better power estimates.
- **Energy Baseline**: Derived heuristically from battery state; override logic if needed.
- **Performance Mode**: The GUI throttles updates and tab‑scoped monitoring to prevent lag.
- **Limits**: Disassembly length ~2000 bytes; process list capped (top 50) for responsiveness.

---

## 🧪 Quick Test

1. Launch PRISM.
2. Click **📂 Load Binary** and choose a small PE/ELF or any binary data file.
3. Click **🔬 Analyze** and explore the tabs.
4. Try **🗂️ Directory Scanner** on your `Downloads`.
5. Use **📊 Generate Report** to save a JSON report.

---

## 📎 Output Files

- **Report JSON**: Full snapshot of file analysis + metrics + trust scores.
- **Raw Analysis JSON**: Export only analysis data.

---

## 🔒 Security & Ethics

- This is a **heuristic** tool; results may include **false positives/negatives**.
- Do **not** rely solely on PRISM to label software as malicious.
- Always validate with professional tooling and follow local laws & ethical guidelines.

---

## 🧱 Limitations

- Disassembler covers a limited subset of x86/x64 opcodes.
- CFG/function detection is approximate.
- Energy/CO₂ estimates are **heuristics**, not hardware sensor readings.
- Import detection is string‑based; packed/encrypted samples may evade detection.

---

## 🗺️ Roadmap Ideas

- Expand opcode coverage & operand decoding.
- Visual CFG (graph rendering).
- Plugin system for detectors (YARA, signature DBs).
- Enhanced PE/ELF parsers (sections, imports/exports tables).
- Cross‑platform packaging (PyInstaller).

---

## 🛠 Troubleshooting

- **No GUI / Tk errors**: Install `python3-tk` (Linux) or use an official Python build with Tk.
- **High CPU usage**: Switch tabs away from Process Monitor; reduce auto‑update intervals.
- **Permission errors**: Some processes/paths require elevated permissions; the app handles and skips.

---

## 📄 License

MIT License — see `LICENSE` (add one if missing).

---

## 👤 Maintainer

**Kushal Chowdary Malempati**

> For issues or feature requests, please open a GitHub issue.

---

## 📚 Acknowledgements

- Inspired by reverse engineering tooling and green computing research. Conversion factor of **0.82 g/Wh** used as a global‑average grid intensity heuristic.

