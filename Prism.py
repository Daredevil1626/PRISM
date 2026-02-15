#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Software Transparency Analyzer with TRUE Reverse Engineering + Energy Analysis
A comprehensive tool combining transparency analysis, reverse engineering, and green computing metrics.

Genesys 2.0 Hackathon - PRISM Project + GRONIT CO2 Green Computing Challenge

IMPROVEMENTS MADE (Process Monitor Optimization):
====================================================
1. PARENT-CHILD RELATIONSHIP DETECTION:
   - Builds complete process tree showing parent-child relationships
   - Tracks which processes have children (parent processes)
   - Displays child count for parent processes
   
2. ZOMBIE PROCESS DETECTION:
   - Identifies zombie processes (terminated but not reaped)
   - Labels them as "Zombie (Safe)" - these are harmless
   - Removed from risk scoring as they pose no threat
   - Just need cleanup by parent process
   
3. ORPHAN PROCESS DETECTION:
   - Identifies orphan processes (parent no longer exists)
   - Labels them as "Orphan (Safe)" - usually harmless
   - Removed from risk scoring unless genuinely suspicious
   - Common in normal system operation
   
4. OPTIMIZED CPU/MEMORY RISK THRESHOLDS:
   - HIGH CPU: Raised from 50% to 80% (Very High CPU)
   - ELEVATED CPU: Raised from 30% to 60% (High CPU)
   - HIGH MEMORY: Raised from 70% to 85% (Very High Memory)
   - ELEVATED MEMORY: Raised from 50% to 70% (High Memory)
   - Reduced risk score weights for CPU/memory usage
   - Rationale: High resource usage ≠ security risk
   
5. ENHANCED PROCESS INFO:
   - Added 'ppid' (parent process ID)
   - Added 'status' (running, sleeping, zombie, etc.)
   - Added 'is_zombie' flag
   - Added 'is_orphan' flag
   - Added 'has_children' flag
   
6. KAGGLE-STYLE KEYWORD DATASET:
   - Replaced 10 hardcoded suspicious keywords with 500+ keyword dataset
   - Keywords categorized by type (spyware, trojan, ransomware, etc.)
   - Severity levels (critical, high, medium, low)
   - Weighted risk scoring based on severity
   - CSV-based for easy updates and customization
   
7. DEEP ARCHIVE & ENCRYPTED FILE SCANNING - UNIVERSAL:
   - Automatically detects and scans ALL archive formats
   - ZIP, 7z, RAR, TAR, GZIP, BZIP2, XZ, LZMA support
   - ISO, CAB, ARJ, LZH detection and basic analysis
   - Extracts and analyzes contents recursively (nested archives supported)
   - Scans both at-once (overall metrics) and one-by-one (per-file analysis)
   - Handles encrypted/password-protected archives
   - Calculates per-file and overall risk/trust scores
   - Entropy analysis for packed/encrypted content detection
   - 3-level deep nesting support for archives within archives
   - Magic byte detection for accurate format identification
   
RESULT: More accurate risk assessment, fewer false positives, better
understanding of process relationships and system state, plus comprehensive
archive analysis capabilities.
"""

import os
import sys
import time
import json
import csv
import hashlib
import psutil
import threading
import subprocess
import struct
import re
import platform
import py7zr
import zipfile
import tarfile
import gzip
import bz2
import lzma
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional, Set
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional, Set
from collections import defaultdict
from dataclasses import dataclass, asdict
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import matplotlib
matplotlib.use('TkAgg')  # Ensures graph window works
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np

# Fix Unicode on Windows
try:
    sys.stdout.reconfigure(encoding='utf-8')
except:
    pass


# ============================================================================
# DEVICE PROFILE & ENERGY ANALYZER (GREEN COMPUTING)
# ============================================================================

# Default CPU TDP - can be adjusted
CPU_TDP_WATTS = 65

def _safe_battery():
    """Returns psutil battery object or None, safely."""
    try:
        return psutil.sensors_battery()
    except Exception:
        return None

def _detect_model_friendly():
    """Best-effort device model detection."""
    system = platform.system().lower()
    
    # Windows
    if system == "windows":
        for args in (["wmic", "csproduct", "get", "vendor,name"],
                     ["wmic", "baseboard", "get", "product,manufacturer"]):
            try:
                out = subprocess.check_output(args, stderr=subprocess.DEVNULL, text=True, timeout=1.5)
                lines = [l.strip() for l in out.splitlines()
                         if l.strip() and "Name" not in l and "Product" not in l]
                if lines:
                    return " ".join(lines[0].split())
            except Exception:
                pass
    
    # macOS
    if system == "darwin":
        try:
            out = subprocess.check_output(["/usr/sbin/ioreg", "-l"],
                                        stderr=subprocess.DEVNULL, text=True, timeout=1.0)
            for line in out.splitlines():
                if "product-name" in line:
                    name = line.split("<")[-1].split(">")[0].strip('"')
                    if name:
                        return name
        except Exception:
            pass
    
    # Linux
    if system == "linux":
        try:
            with open('/sys/class/dmi/id/sys_vendor', 'r', encoding='utf-8', errors='ignore') as f:
                vendor = f.read().strip()
            with open('/sys/class/dmi/id/product_name', 'r', encoding='utf-8', errors='ignore') as f:
                product = f.read().strip()
            model = f"{vendor} {product}".strip()
            if model:
                return model
        except Exception:
            pass
    
    return platform.node() or "Unknown-Device"

def _estimate_idle_watts(batt) -> float:
    """Heuristic baseline idle power (Watts)."""
    desktop_fallback = 15.0
    laptop_batt_idle_hi = 8.0
    laptop_batt_idle_lo = 10.0
    laptop_plugged_idle = 12.0
    
    if batt is None:
        return desktop_fallback
    
    try:
        if batt.power_plugged:
            return laptop_plugged_idle
        if batt.percent is not None and batt.percent >= 50:
            return laptop_batt_idle_hi
        return laptop_batt_idle_lo
    except Exception:
        return desktop_fallback

def get_device_profile():
    """
    Detects OS, device model, battery state, and baseline power.
    Returns dict with system info and energy parameters.
    """
    system = platform.system()
    model = _detect_model_friendly()
    batt = _safe_battery()
    battery_present = bool(batt is not None)
    battery_percent = float(batt.percent) if (batt and batt.percent is not None) else None
    battery_plugged = bool(batt.power_plugged) if batt else None
    baseline_idle_watts = _estimate_idle_watts(batt)
    
    return {
        "system": system,
        "model": model,
        "battery_present": battery_present,
        "battery_percent": battery_percent,
        "battery_plugged": battery_plugged,
        "baseline_idle_watts": baseline_idle_watts,
    }

# Initialize device profile
DEVICE_PROFILE = get_device_profile()
IDLE_W_BASELINE = DEVICE_PROFILE.get('baseline_idle_watts', 10.0)
DEVICE_MODEL = DEVICE_PROFILE.get('model', 'Unknown')
SYSTEM_NAME = DEVICE_PROFILE.get('system', 'Unknown')


class EnergyAnalyzer:
    """Tracks energy consumption and calculates green computing metrics."""
    
    def __init__(self):
        self.baseline_cpu = 0
        self.baseline_energy = 0
        self.energy_history = []
        self.time_history = []
        self.start_time = None
        
    def calculate_energy(self, cpu_percent, interval=1, idle_watts=0.0):
        """Calculate energy consumption in Joules."""
        dynamic_watts = (cpu_percent / 100.0) * CPU_TDP_WATTS
        power_watts = idle_watts + dynamic_watts
        return power_watts * interval
    
    def measure_baseline(self, duration=2):
        """Measure system baseline energy consumption."""
        cpu_samples = []
        for _ in range(duration):
            cpu = psutil.cpu_percent(interval=1)
            cpu_samples.append(cpu)
        
        self.baseline_cpu = sum(cpu_samples) / len(cpu_samples)
        self.baseline_energy = self.calculate_energy(
            self.baseline_cpu, 
            interval=duration, 
            idle_watts=IDLE_W_BASELINE
        )
        return self.baseline_energy
    
    def start_monitoring(self):
        """Start energy monitoring session."""
        self.energy_history = []
        self.time_history = []
        self.start_time = time.time()
        
    def record_sample(self, cpu_percent):
        """Record an energy sample."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        energy = self.calculate_energy(cpu_percent, interval=1, idle_watts=IDLE_W_BASELINE)
        
        self.time_history.append(elapsed)
        self.energy_history.append(energy)
        
    def calculate_metrics(self):
        """Calculate comprehensive energy metrics."""
        if not self.energy_history:
            return {
                'total_energy_j': 0,
                'avg_power_w': 0,
                'peak_power_w': 0,
                'energy_waste_j': 0,
                'co2_grams': 0,
                'efficiency_score': 0
            }
        
        total_energy = sum(self.energy_history)
        duration = self.time_history[-1] if self.time_history else 1
        avg_power = total_energy / duration if duration > 0 else 0
        peak_power = max(self.energy_history) if self.energy_history else 0
        
        # Energy waste (compared to baseline)
        baseline_per_sec = self.calculate_energy(self.baseline_cpu, interval=1, idle_watts=IDLE_W_BASELINE)
        expected_energy = baseline_per_sec * len(self.energy_history)
        energy_waste = max(0, total_energy - expected_energy)
        
        # CO2 emissions (0.82g CO2 per Wh)
        # Convert Joules to Wh: J / 3600 = Wh
        energy_wh = total_energy / 3600
        co2_grams = energy_wh * 0.82  # 0.82g CO2 per Wh
        
        # Efficiency score (0-100)
        if expected_energy > 0:
            efficiency_ratio = expected_energy / total_energy
            efficiency_score = min(100, efficiency_ratio * 100)
        else:
            efficiency_score = 100
        
        return {
            'total_energy_j': round(total_energy, 2),
            'avg_power_w': round(avg_power, 2),
            'peak_power_w': round(peak_power, 2),
            'energy_waste_j': round(energy_waste, 2),
            'co2_grams': round(co2_grams, 4),
            'efficiency_score': round(efficiency_score, 2),
            'baseline_energy_j': round(expected_energy, 2)
        }


# ============================================================================
# TRUE REVERSE ENGINEERING COMPONENTS
# ============================================================================

@dataclass
class Instruction:
    """Represents a disassembled instruction"""
    address: int
    opcode: bytes
    mnemonic: str
    operands: str
    size: int
    is_branch: bool = False
    is_call: bool = False
    is_return: bool = False
    target_address: Optional[int] = None


@dataclass
class BasicBlock:
    """Represents a basic block in control flow"""
    start_address: int
    end_address: int
    instructions: List[Instruction]
    successors: List[int]
    predecessors: List[int]
    is_entry: bool = False
    is_exit: bool = False


@dataclass
class Function:
    """Represents a discovered function"""
    start_address: int
    end_address: int
    name: str
    basic_blocks: List[BasicBlock]
    calls_to: List[int]
    called_from: List[int]
    local_vars: int
    parameters: int
    complexity: int  # Cyclomatic complexity


class X86Disassembler:
    """x86/x64 disassembler"""
    
    # Common x86/x64 opcode patterns
    OPCODES = {
        # Control flow
        0xE8: ("call", 4, True, False, False),
        0xE9: ("jmp", 4, True, False, False),
        0xEB: ("jmp", 1, True, False, False),
        0xC3: ("ret", 0, False, False, True),
        0xC2: ("ret", 2, False, False, True),
        
        # Conditional jumps
        0x74: ("je", 1, True, False, False),
        0x75: ("jne", 1, True, False, False),
        0x7C: ("jl", 1, True, False, False),
        0x7D: ("jge", 1, True, False, False),
        0x7E: ("jle", 1, True, False, False),
        0x7F: ("jg", 1, True, False, False),
        
        # Stack operations
        0x50: ("push", 0, False, False, False),
        0x51: ("push", 0, False, False, False),
        0x52: ("push", 0, False, False, False),
        0x53: ("push", 0, False, False, False),
        0x58: ("pop", 0, False, False, False),
        0x59: ("pop", 0, False, False, False),
        0x5A: ("pop", 0, False, False, False),
        0x5B: ("pop", 0, False, False, False),
        
        0x90: ("nop", 0, False, False, False),
        0xCC: ("int3", 0, False, False, False),
        
        # MOV instructions
        0x88: ("mov", 1, False, False, False),
        0x89: ("mov", 1, False, False, False),
        0x8A: ("mov", 1, False, False, False),
        0x8B: ("mov", 1, False, False, False),
        
        # Arithmetic
        0x01: ("add", 1, False, False, False),
        0x29: ("sub", 1, False, False, False),
        0x31: ("xor", 1, False, False, False),
        0x09: ("or", 1, False, False, False),
        0x21: ("and", 1, False, False, False),
    }
    
    def __init__(self, data: bytes, base_address: int = 0x400000):
        self.data = data
        self.base_address = base_address
        
    def disassemble(self, start: int = 0, length: int = None) -> List[Instruction]:
        """Disassemble binary data into instructions"""
        if length is None:
            length = min(len(self.data) - start, 2000)  # Limit for performance
            
        instructions = []
        offset = start
        end = min(start + length, len(self.data))
        
        while offset < end:
            try:
                instr = self._decode_instruction(offset)
                if instr:
                    instructions.append(instr)
                    offset += instr.size
                else:
                    offset += 1
            except:
                offset += 1
                
        return instructions
    
    def _decode_instruction(self, offset: int) -> Optional[Instruction]:
        """Decode a single instruction at offset"""
        if offset >= len(self.data):
            return None
            
        opcode = self.data[offset]
        
        if opcode in self.OPCODES:
            mnemonic, operand_size, is_branch, is_call, is_return = self.OPCODES[opcode]
            
            operands = ""
            target_address = None
            instr_size = 1 + operand_size
            
            if operand_size > 0 and offset + instr_size <= len(self.data):
                operand_bytes = self.data[offset + 1:offset + 1 + operand_size]
                
                if is_branch or is_call:
                    if operand_size == 1:
                        rel_offset = struct.unpack('b', operand_bytes)[0]
                    elif operand_size == 4:
                        rel_offset = struct.unpack('<i', operand_bytes)[0]
                    else:
                        rel_offset = 0
                    
                    target_address = self.base_address + offset + instr_size + rel_offset
                    operands = f"0x{target_address:x}"
                else:
                    operands = operand_bytes.hex()
            
            return Instruction(
                address=self.base_address + offset,
                opcode=self.data[offset:offset + instr_size],
                mnemonic=mnemonic,
                operands=operands,
                size=instr_size,
                is_branch=is_branch,
                is_call=is_call,
                is_return=is_return,
                target_address=target_address
            )
        
        return Instruction(
            address=self.base_address + offset,
            opcode=bytes([opcode]),
            mnemonic="db",
            operands=f"0x{opcode:02x}",
            size=1
        )


class ControlFlowAnalyzer:
    """Analyzes control flow and creates CFG"""
    
    def __init__(self, instructions: List[Instruction]):
        self.instructions = instructions
        self.basic_blocks = []
        self.functions = []
        
    def analyze(self) -> Dict:
        """Perform complete control flow analysis"""
        self._build_basic_blocks()
        self._detect_functions()
        metrics = self._calculate_metrics()
        
        return {
            'basic_blocks_count': len(self.basic_blocks),
            'functions_count': len(self.functions),
            'metrics': metrics,
            'basic_blocks': [self._block_summary(bb) for bb in self.basic_blocks[:20]],
            'functions': [self._function_summary(f) for f in self.functions]
        }
    
    def _build_basic_blocks(self):
        """Build basic blocks from instructions"""
        if not self.instructions:
            return
        
        leaders = {self.instructions[0].address}
        
        for i, instr in enumerate(self.instructions):
            if instr.is_branch or instr.is_call or instr.is_return:
                if i + 1 < len(self.instructions):
                    leaders.add(self.instructions[i + 1].address)
            
            if instr.target_address:
                leaders.add(instr.target_address)
        
        leaders_list = sorted(leaders)
        
        for i, leader_addr in enumerate(leaders_list):
            if i + 1 < len(leaders_list):
                next_leader = leaders_list[i + 1]
            else:
                next_leader = self.instructions[-1].address + self.instructions[-1].size
            
            block_instrs = [instr for instr in self.instructions 
                          if leader_addr <= instr.address < next_leader]
            
            if block_instrs:
                bb = BasicBlock(
                    start_address=block_instrs[0].address,
                    end_address=block_instrs[-1].address,
                    instructions=block_instrs,
                    successors=[],
                    predecessors=[]
                )
                
                last_instr = block_instrs[-1]
                if last_instr.is_return:
                    bb.is_exit = True
                elif last_instr.target_address:
                    bb.successors.append(last_instr.target_address)
                    if not last_instr.mnemonic.startswith('jmp'):
                        if i + 1 < len(leaders_list):
                            bb.successors.append(leaders_list[i + 1])
                elif i + 1 < len(leaders_list):
                    bb.successors.append(leaders_list[i + 1])
                
                self.basic_blocks.append(bb)
        
        for bb in self.basic_blocks:
            for succ_addr in bb.successors:
                for other_bb in self.basic_blocks:
                    if other_bb.start_address == succ_addr:
                        other_bb.predecessors.append(bb.start_address)
    
    def _detect_functions(self):
        """Detect function boundaries"""
        function_starts = set()
        
        for instr in self.instructions:
            if instr.is_call and instr.target_address:
                function_starts.add(instr.target_address)
        
        if self.instructions:
            function_starts.add(self.instructions[0].address)
        
        for start_addr in sorted(function_starts):
            func_blocks = [bb for bb in self.basic_blocks 
                          if bb.start_address >= start_addr]
            
            if func_blocks:
                end_addr = func_blocks[0].end_address
                for bb in func_blocks:
                    if bb.is_exit:
                        end_addr = max(end_addr, bb.end_address)
                        break
                    end_addr = max(end_addr, bb.end_address)
                
                func = Function(
                    start_address=start_addr,
                    end_address=end_addr,
                    name=f"sub_{start_addr:x}",
                    basic_blocks=[bb for bb in func_blocks 
                                 if start_addr <= bb.start_address <= end_addr],
                    calls_to=[],
                    called_from=[],
                    local_vars=0,
                    parameters=0,
                    complexity=len([bb for bb in func_blocks 
                                  if start_addr <= bb.start_address <= end_addr])
                )
                self.functions.append(func)
    
    def _calculate_metrics(self) -> Dict:
        """Calculate code complexity metrics"""
        total_instructions = len(self.instructions)
        total_blocks = len(self.basic_blocks)
        total_functions = len(self.functions)
        
        avg_complexity = 0
        if self.functions:
            avg_complexity = sum(f.complexity for f in self.functions) / len(self.functions)
        
        total_edges = sum(len(bb.successors) for bb in self.basic_blocks)
        
        return {
            'total_instructions': total_instructions,
            'total_basic_blocks': total_blocks,
            'total_functions': total_functions,
            'total_edges': total_edges,
            'avg_cyclomatic_complexity': round(avg_complexity, 2),
            'max_function_complexity': max([f.complexity for f in self.functions], default=0)
        }
    
    def _block_summary(self, bb: BasicBlock) -> Dict:
        """Convert basic block to summary dict"""
        return {
            'start': f"0x{bb.start_address:x}",
            'end': f"0x{bb.end_address:x}",
            'size': len(bb.instructions),
            'successors': len(bb.successors),
            'is_entry': bb.is_entry,
            'is_exit': bb.is_exit
        }
    
    def _function_summary(self, func: Function) -> Dict:
        """Convert function to summary dict"""
        return {
            'name': func.name,
            'start': f"0x{func.start_address:x}",
            'end': f"0x{func.end_address:x}",
            'blocks': len(func.basic_blocks),
            'complexity': func.complexity
        }


class CryptoDetector:
    """Detect cryptographic constants and algorithms"""
    
    CRYPTO_CONSTANTS = {
        b'\x67\x45\x23\x01': 'MD5_INIT',
        b'\xef\xcd\xab\x89': 'MD5_INIT',
        b'\x98\xba\xdc\xfe': 'MD5_INIT',
        b'\x10\x32\x54\x76': 'MD5_INIT',
        b'\x67\x45\x23\x01\xef\xcd\xab\x89': 'SHA1_INIT',
        b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5': 'AES_SBOX',
        b'\x00\x01\x00\x01': 'RSA_F4',
    }
    
    @staticmethod
    def detect_crypto(data: bytes) -> Dict:
        """Detect cryptographic constants and algorithms"""
        findings = {'constants': [], 'high_entropy_blocks': 0}
        
        for const, name in CryptoDetector.CRYPTO_CONSTANTS.items():
            if const in data:
                findings['constants'].append(name.split('_')[0])
        
        # Count high-entropy blocks
        block_size = 16
        for i in range(0, len(data) - block_size, block_size):
            block = data[i:i + block_size]
            if CryptoDetector._calculate_entropy(block) > 7.5:
                findings['high_entropy_blocks'] += 1
        
        findings['constants'] = list(set(findings['constants']))
        return findings
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy"""
        import math
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy


class BinaryFormatAnalyzer:
    """Analyze binary file formats (PE/ELF)"""
    
    @staticmethod
    def analyze(data: bytes) -> Optional[Dict]:
        """Detect and analyze binary format"""
        # Check PE
        if len(data) >= 64 and data[:2] == b'MZ':
            return BinaryFormatAnalyzer._analyze_pe(data)
        
        # Check ELF
        if len(data) >= 64 and data[:4] == b'\x7fELF':
            return BinaryFormatAnalyzer._analyze_elf(data)
        
        return None
    
    @staticmethod
    def _analyze_pe(data: bytes) -> Dict:
        """Analyze PE file"""
        try:
            e_lfanew = struct.unpack('<I', data[60:64])[0]
            if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
                return None
            
            machine = struct.unpack('<H', data[e_lfanew + 4:e_lfanew + 6])[0]
            num_sections = struct.unpack('<H', data[e_lfanew + 6:e_lfanew + 8])[0]
            
            machine_types = {0x14c: 'i386', 0x8664: 'x86_64', 0x1c0: 'ARM', 0xaa64: 'ARM64'}
            
            return {
                'format': 'PE',
                'architecture': machine_types.get(machine, f'Unknown (0x{machine:x})'),
                'sections': num_sections
            }
        except:
            return None
    
    @staticmethod
    def _analyze_elf(data: bytes) -> Dict:
        """Analyze ELF file"""
        try:
            ei_class = data[4]
            e_machine = struct.unpack('<H', data[18:20])[0]
            
            class_types = {1: '32-bit', 2: '64-bit'}
            machine_types = {0x03: 'x86', 0x3e: 'x86_64', 0x28: 'ARM', 0xb7: 'ARM64'}
            
            return {
                'format': 'ELF',
                'class': class_types.get(ei_class, 'Unknown'),
                'architecture': machine_types.get(e_machine, f'Unknown (0x{e_machine:x})')
            }
        except:
            return None


# ============================================================================
# ENHANCED REVERSE ENGINEERING ENGINE
# ============================================================================

class ReverseEngineeringEngine:
    """Enhanced core engine with TRUE reverse engineering capabilities"""
    
    def __init__(self):
        self.analysis_results = {}
        
    def analyze_binary(self, file_path: str) -> Dict[str, Any]:
        """Perform comprehensive static and reverse engineering analysis"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        results = {
            'file_info': self._get_file_info(file_path, data),
            'strings_analysis': self._extract_strings(file_path),
            'entropy_analysis': self._calculate_entropy(file_path),
            'imports_exports': self._analyze_imports_exports(file_path),
            'suspicious_patterns': self._detect_suspicious_patterns(file_path),
            
            # NEW: True Reverse Engineering Features
            'binary_format': BinaryFormatAnalyzer.analyze(data),
            'disassembly': self._perform_disassembly(data),
            'control_flow': self._analyze_control_flow(data),
            'crypto_detection': CryptoDetector.detect_crypto(data),
            'code_patterns': self._analyze_code_patterns(data)
        }
        return results
    
    def _get_file_info(self, file_path: str, data: bytes = None) -> Dict[str, Any]:
        """Extract file information"""
        stat = os.stat(file_path)
        
        if data is None:
            with open(file_path, 'rb') as f:
                data = f.read()
        
        hash_md5 = hashlib.md5(data).hexdigest()
        hash_sha256 = hashlib.sha256(data).hexdigest()
        
        return {
            'filename': os.path.basename(file_path),
            'size_bytes': stat.st_size,
            'size_mb': round(stat.st_size / (1024 * 1024), 2),
            'md5': hash_md5,
            'sha256': hash_sha256,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
        }
    
    def _extract_strings(self, file_path: str, min_length: int = 4) -> Dict[str, Any]:
        """Extract readable strings from binary"""
        strings = []
        suspicious_keywords = [
            'password', 'secret', 'api_key', 'token', 'credential',
            'admin', 'root', 'backdoor', 'malware', 'virus'
        ]
        
        try:
            with open(file_path, 'rb') as f:
                result = ""
                for byte in f.read():
                    if 32 <= byte <= 126:
                        result += chr(byte)
                    else:
                        if len(result) >= min_length:
                            strings.append(result)
                        result = ""
        except Exception as e:
            return {'error': str(e), 'strings_found': 0}
        
        suspicious = [s for s in strings if any(kw in s.lower() for kw in suspicious_keywords)]
        
        return {
            'total_strings': len(strings),
            'suspicious_strings': suspicious[:20],
            'sample_strings': strings[:50],
            'suspicious_count': len(suspicious)
        }
    
    def _calculate_entropy(self, file_path: str) -> Dict[str, float]:
        """Calculate file entropy"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return {'entropy': 0.0, 'assessment': 'Empty file'}
            
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0.0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    freq = count / data_len
                    entropy -= freq * np.log2(freq)
            
            if entropy > 7.5:
                assessment = "Very High - Likely Encrypted/Packed"
            elif entropy > 6.5:
                assessment = "High - Possible Obfuscation"
            elif entropy > 4.5:
                assessment = "Medium - Normal Executable"
            else:
                assessment = "Low - Likely Text/Data File"
            
            return {
                'entropy': round(entropy, 3),
                'max_entropy': 8.0,
                'assessment': assessment
            }
        except Exception as e:
            return {'error': str(e), 'entropy': 0.0}
    
    def _analyze_imports_exports(self, file_path: str) -> Dict[str, Any]:
        """Analyze imports and exports"""
        risky_imports = [
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'SetWindowsHookEx', 'GetAsyncKeyState', 'InternetOpen',
            'URLDownloadToFile', 'WinExec', 'ShellExecute'
        ]
        
        imports_found = []
        suspicious_imports = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                content_str = str(content)
                
                for risky_import in risky_imports:
                    if risky_import.lower() in content_str.lower():
                        imports_found.append(risky_import)
                        suspicious_imports.append(risky_import)
        except Exception as e:
            return {'error': str(e)}
        
        return {
            'total_imports': len(imports_found),
            'suspicious_imports': suspicious_imports,
            'risk_level': 'High' if len(suspicious_imports) > 3 else 'Medium' if len(suspicious_imports) > 0 else 'Low'
        }
    
    def _detect_suspicious_patterns(self, file_path: str) -> Dict[str, Any]:
        """Detect suspicious patterns in binary"""
        patterns = {
            'url_patterns': 0,
            'ip_patterns': 0,
            'registry_keys': 0,
            'encoded_data': 0
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read().decode('latin-1', errors='ignore')
                
                patterns['url_patterns'] = len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])+', content))
                patterns['ip_patterns'] = len(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content))
                patterns['registry_keys'] = content.lower().count('hkey_')
                patterns['encoded_data'] = len(re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', content))
        except Exception as e:
            patterns['error'] = str(e)
        
        return patterns
    
    # NEW METHODS FOR TRUE REVERSE ENGINEERING
    
    def _perform_disassembly(self, data: bytes) -> Dict:
        """Perform disassembly on binary"""
        try:
            disasm = X86Disassembler(data)
            instructions = disasm.disassemble(0, min(len(data), 2000))
            
            return {
                'total_instructions': len(instructions),
                'sample_instructions': [
                    {
                        'address': f"0x{i.address:08x}",
                        'opcode': i.opcode.hex(),
                        'mnemonic': i.mnemonic,
                        'operands': i.operands
                    } for i in instructions[:50]
                ]
            }
        except Exception as e:
            return {'error': str(e), 'total_instructions': 0}
    
    def _analyze_control_flow(self, data: bytes) -> Dict:
        """Analyze control flow"""
        try:
            disasm = X86Disassembler(data)
            instructions = disasm.disassemble(0, min(len(data), 2000))
            
            if instructions:
                cfg = ControlFlowAnalyzer(instructions)
                return cfg.analyze()
            
            return {'error': 'No instructions to analyze'}
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_code_patterns(self, data: bytes) -> Dict:
        """Analyze code patterns"""
        try:
            disasm = X86Disassembler(data)
            instructions = disasm.disassemble(0, min(len(data), 2000))
            
            patterns = {
                'calls': sum(1 for i in instructions if i.is_call),
                'jumps': sum(1 for i in instructions if i.is_branch),
                'returns': sum(1 for i in instructions if i.is_return),
                'stack_ops': sum(1 for i in instructions if i.mnemonic in ['push', 'pop']),
                'arithmetic': sum(1 for i in instructions if i.mnemonic in ['add', 'sub', 'mul', 'div', 'xor', 'and', 'or']),
            }
            
            return patterns
        except Exception as e:
            return {'error': str(e)}


# ============================================================================
# MALICIOUS KEYWORD DATABASE (Kaggle-style Dataset)
# ============================================================================

class MaliciousKeywordDatabase:
    """
    Manages a comprehensive database of suspicious process keywords.
    Loads from CSV file with categorization and severity levels.
    """
    
    def __init__(self, csv_path: str = None):
        """Initialize keyword database from CSV file"""
        self.keywords = {}  # keyword -> {'category': str, 'severity': str, 'weight': float}
        self.severity_weights = {
            'critical': 0.8,
            'high': 0.5,
            'medium': 0.3,
            'low': 0.1
        }
        
        # Default to embedded keywords if no CSV provided
        if csv_path and os.path.exists(csv_path):
            self._load_from_csv(csv_path)
        else:
            self._load_default_keywords()
    
    def _load_from_csv(self, csv_path: str):
        """Load keywords from CSV file"""
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    keyword = row['keyword'].lower().strip()
                    category = row.get('category', 'unknown').strip()
                    severity = row.get('severity', 'medium').lower().strip()
                    
                    self.keywords[keyword] = {
                        'category': category,
                        'severity': severity,
                        'weight': self.severity_weights.get(severity, 0.3)
                    }
            
            print(f"[KeywordDB] Loaded {len(self.keywords)} keywords from {csv_path}")
        except Exception as e:
            print(f"[KeywordDB] Error loading CSV: {e}, using defaults")
            self._load_default_keywords()
    
    def _load_default_keywords(self):
        """Load default keyword set as fallback"""
        default_keywords = [
            # Critical threats
            ('keylog', 'spyware', 'critical'),
            ('keylogger', 'spyware', 'critical'),
            ('backdoor', 'trojan', 'critical'),
            ('trojan', 'trojan', 'critical'),
            ('virus', 'malware', 'critical'),
            ('malware', 'malware', 'critical'),
            ('ransomware', 'ransomware', 'critical'),
            ('rootkit', 'rootkit', 'critical'),
            ('rat', 'rat', 'critical'),
            ('botnet', 'botnet', 'critical'),
            
            # High threats
            ('miner', 'cryptominer', 'high'),
            ('coinminer', 'cryptominer', 'high'),
            ('hack', 'hacking', 'high'),
            ('crack', 'cracking', 'high'),
            ('inject', 'injection', 'high'),
            ('exploit', 'exploit', 'high'),
            ('stealer', 'infostealer', 'high'),
            ('spy', 'spyware', 'high'),
            ('dropper', 'dropper', 'high'),
            ('worm', 'worm', 'high'),
            
            # Medium threats
            ('keygen', 'cracking', 'medium'),
            ('payload', 'exploit', 'medium'),
            ('obfuscated', 'obfuscation', 'medium'),
            ('crypter', 'crypter', 'medium'),
            ('macro', 'macro_malware', 'medium'),
            ('phish', 'phishing', 'medium'),
            ('adware', 'adware', 'medium'),
            ('suspicious', 'suspicious', 'medium'),
        ]
        
        for keyword, category, severity in default_keywords:
            self.keywords[keyword] = {
                'category': category,
                'severity': severity,
                'weight': self.severity_weights.get(severity, 0.3)
            }
        
        print(f"[KeywordDB] Loaded {len(self.keywords)} default keywords")
    
    def check_process_name(self, process_name: str) -> Tuple[bool, float, List[str]]:
        """
        Check if process name contains suspicious keywords.
        
        Returns:
            (is_suspicious, risk_score, matched_keywords)
        """
        name_lower = process_name.lower()
        matches = []
        total_weight = 0.0
        
        for keyword, info in self.keywords.items():
            if keyword in name_lower:
                matches.append(f"{keyword}({info['severity']})")
                total_weight += info['weight']
        
        # Cap the total weight at 0.8 to leave room for other risk factors
        risk_score = min(total_weight, 0.8)
        is_suspicious = len(matches) > 0
        
        return is_suspicious, risk_score, matches


# ============================================================================
# RESOURCE MONITORING (Original Code)
# ============================================================================

class ResourceMonitor:
    """Monitor system resource usage including energy consumption"""
    
    def __init__(self, keyword_db_path: str = None):
        self.monitoring = False
        self.metrics = {
            'cpu': [],
            'memory': [],
            'network_sent': [],
            'network_recv': [],
            'disk_read': [],
            'disk_write': [],
            'timestamps': [],
            'energy': []  # NEW: Energy tracking
        }
        self.start_time = None
        self.monitor_thread = None
        self.initial_network = None
        self.initial_disk = None
        self.process_cache = {}
        self.process_history = []
        self.energy_analyzer = EnergyAnalyzer()  # NEW
        
        # Initialize keyword database
        if keyword_db_path is None:
            # Try to find CSV in same directory as script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            keyword_db_path = os.path.join(script_dir, 'malicious_process_keywords.csv')
        
        self.keyword_db = MaliciousKeywordDatabase(keyword_db_path)
        
    def get_running_processes(self) -> List[Dict]:
        """Get list of running processes with risk analysis, including parent-child, zombie, and orphan detection"""
        processes = []
        
        # Get all processes first
        all_procs = []
        for proc in psutil.process_iter(['pid', 'name', 'ppid', 'status']):
            try:
                pid = proc.info['pid']
                if pid == 0 or pid == 4:  # Skip system processes
                    continue
                all_procs.append(proc)
            except:
                continue
        
        # Build process tree for parent-child relationship analysis
        process_tree = {}
        zombie_pids = set()
        orphan_pids = set()
        parent_pids = set()
        
        for proc in all_procs:
            try:
                pid = proc.info['pid']
                ppid = proc.info.get('ppid', None)
                status = proc.info.get('status', None)
                
                # Check for zombie processes
                if status == psutil.STATUS_ZOMBIE:
                    zombie_pids.add(pid)
                
                # Track parent-child relationships
                if ppid is not None:
                    if ppid not in process_tree:
                        process_tree[ppid] = []
                    process_tree[ppid].append(pid)
                    parent_pids.add(ppid)
            except:
                continue
        
        # Detect orphan processes (parent doesn't exist or is init/system)
        for proc in all_procs:
            try:
                pid = proc.info['pid']
                ppid = proc.info.get('ppid', None)
                
                # A process is orphaned if its parent is gone or is init (pid 1)
                if ppid and ppid not in [p.info['pid'] for p in all_procs]:
                    orphan_pids.add(pid)
            except:
                continue
        
        # Limit to top 100 processes by CPU to improve performance
        all_procs = all_procs[:100]
        
        for proc in all_procs:
            try:
                pid = proc.info['pid']
                
                # Get process details
                p = psutil.Process(pid)
                
                try:
                    name = proc.info['name'] or 'Unknown'
                    # Reduce CPU check interval for better performance
                    cpu = p.cpu_percent(interval=0.05)  # Faster check
                    
                    try:
                        memory = p.memory_percent()
                        username = p.username()
                        ppid = p.ppid()
                        status = p.status()
                    except:
                        memory = 0
                        username = 'System'
                        ppid = None
                        status = 'unknown'
                    
                    # Get additional info (with error handling for access denied)
                    try:
                        exe_path = p.exe()
                    except:
                        exe_path = 'Access Denied'
                    
                    try:
                        cmdline = ' '.join(p.cmdline()[:3])  # First 3 args
                    except:
                        cmdline = 'Access Denied'
                    
                    # Calculate risk score
                    risk_score = 0.0
                    risk_factors = []
                    
                    # Check for zombie process - SAFE, just needs cleanup
                    is_zombie = pid in zombie_pids
                    if is_zombie:
                        risk_factors.append('Zombie (Safe)')
                        # Don't add to risk score - zombies are harmless
                    
                    # Check for orphan process - SAFE unless malicious
                    is_orphan = pid in orphan_pids
                    if is_orphan and not is_zombie:
                        risk_factors.append('Orphan (Safe)')
                        # Don't add to risk score - orphans are usually harmless
                    
                    # Check if this is a parent process
                    has_children = pid in parent_pids
                    if has_children:
                        child_count = len(process_tree.get(pid, []))
                        risk_factors.append(f'Parent ({child_count} children)')
                        # Don't add to risk score - being a parent is normal
                    
                    # ADJUSTED: Only flag VERY high CPU/memory usage as risky
                    # Normal high usage is not necessarily a security risk
                    if cpu > 80:  # Raised threshold from 50 to 80
                        risk_score += 0.2  # Reduced from 0.3
                        risk_factors.append('Very High CPU')
                    elif cpu > 60:  # Raised threshold from 30 to 60
                        risk_score += 0.1  # Reduced from 0.15
                        risk_factors.append('High CPU')
                    
                    # ADJUSTED: Only flag VERY high memory usage as risky
                    if memory > 85:  # Raised threshold from 70 to 85
                        risk_score += 0.15  # Reduced from 0.25
                        risk_factors.append('Very High Memory')
                    elif memory > 70:  # Raised threshold from 50 to 70
                        risk_score += 0.05  # Reduced from 0.1
                        risk_factors.append('High Memory')
                    
                    # Check against keyword database (500+ keywords with severity levels)
                    is_suspicious, keyword_risk, matched_keywords = self.keyword_db.check_process_name(name)
                    
                    if is_suspicious:
                        risk_score += keyword_risk
                        # Show first 3 matches to avoid cluttering
                        keyword_summary = ', '.join(matched_keywords[:3])
                        if len(matched_keywords) > 3:
                            keyword_summary += f' +{len(matched_keywords)-3} more'
                        risk_factors.append(f'Suspicious: {keyword_summary}')
                    
                    # Very short or obfuscated names (but only if not a known system process)
                    known_short_names = {'sh', 'ps', 'ls', 'vi', 'cp', 'mv', 'rm', 'dd'}
                    if len(name) <= 2 and name.lower() not in known_short_names:
                        risk_score += 0.1
                        risk_factors.append('Short/Hidden Name')
                    elif name.count('.') == 0 and len(name) > 2:  # No extension
                        # Only flag if not common executable names
                        common_no_ext = {'python', 'java', 'node', 'ruby', 'perl', 'bash', 'zsh'}
                        if name.lower() not in common_no_ext:
                            risk_score += 0.05
                            risk_factors.append('No Extension')
                    
                    # Suspicious execution paths
                    if exe_path != 'Access Denied':
                        suspicious_paths = ['temp', 'appdata\\local\\temp', 'downloads']
                        if any(path in exe_path.lower() for path in suspicious_paths):
                            risk_score += 0.2
                            risk_factors.append('Suspicious Path')
                    
                    # Determine risk level
                    if risk_score >= 0.6:
                        risk_level = 'CRITICAL'
                        risk_color = '#ff0000'
                    elif risk_score >= 0.4:
                        risk_level = 'HIGH'
                        risk_color = '#ff6600'
                    elif risk_score >= 0.2:
                        risk_level = 'MEDIUM'
                        risk_color = '#ffaa00'
                    else:
                        risk_level = 'LOW'
                        risk_color = '#00aa00'
                    
                    processes.append({
                        'pid': pid,
                        'name': name[:30],
                        'cpu': round(cpu, 1),
                        'memory': round(memory, 1),
                        'username': username[:20],
                        'exe_path': exe_path[:50],
                        'cmdline': cmdline[:50],
                        'risk_score': round(risk_score, 2),
                        'risk_level': risk_level,
                        'risk_color': risk_color,
                        'risk_factors': ', '.join(risk_factors) if risk_factors else 'None',
                        'ppid': ppid,
                        'status': status,
                        'is_zombie': is_zombie,
                        'is_orphan': is_orphan,
                        'has_children': has_children
                    })
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort by risk score descending, then by CPU
        processes.sort(key=lambda x: (x['risk_score'], x['cpu']), reverse=True)
        return processes
        
    def start_monitoring(self):
        """Start monitoring resources including energy"""
        self.monitoring = True
        self.start_time = time.time()
        self.initial_network = psutil.net_io_counters()
        self.initial_disk = psutil.disk_io_counters()
        
        # Initialize energy monitoring
        self.energy_analyzer.measure_baseline(duration=1)
        self.energy_analyzer.start_monitoring()
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def _monitor_loop(self):
        """Main monitoring loop with energy tracking"""
        while self.monitoring:
            try:
                # CPU
                cpu_percent = psutil.cpu_percent(interval=0.1)
                
                # Record energy sample
                self.energy_analyzer.record_sample(cpu_percent)
                
                # Memory
                memory = psutil.virtual_memory()
                memory_mb = memory.used / (1024 * 1024)
                
                # Network
                net_current = psutil.net_io_counters()
                net_sent_mb = (net_current.bytes_sent - self.initial_network.bytes_sent) / (1024 * 1024)
                net_recv_mb = (net_current.bytes_recv - self.initial_network.bytes_recv) / (1024 * 1024)
                
                # Disk I/O
                try:
                    disk_current = psutil.disk_io_counters()
                    disk_read_mb = (disk_current.read_bytes - self.initial_disk.read_bytes) / (1024 * 1024)
                    disk_write_mb = (disk_current.write_bytes - self.initial_disk.write_bytes) / (1024 * 1024)
                except:
                    disk_read_mb = 0
                    disk_write_mb = 0
                
                # Timestamp
                elapsed = time.time() - self.start_time
                
                # Energy (latest from analyzer)
                energy = self.energy_analyzer.energy_history[-1] if self.energy_analyzer.energy_history else 0
                
                # Store metrics
                self.metrics['cpu'].append(cpu_percent)
                self.metrics['memory'].append(memory_mb)
                self.metrics['network_sent'].append(net_sent_mb)
                self.metrics['network_recv'].append(net_recv_mb)
                self.metrics['disk_read'].append(disk_read_mb)
                self.metrics['disk_write'].append(disk_write_mb)
                self.metrics['timestamps'].append(elapsed)
                self.metrics['energy'].append(energy)
                
                time.sleep(0.5)  # Balanced monitoring - 2 updates per second
            except Exception as e:
                print(f"Monitoring error: {e}")
                break
                
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
    
    def get_metrics(self) -> Dict:
        """Get current metrics"""
        return self.metrics.copy()
    
    def calculate_summary(self) -> Dict:
        """Calculate summary statistics including energy metrics"""
        if not self.metrics['cpu']:
            return {
                'cpu_avg': 0, 'cpu_max': 0,
                'memory_avg': 0, 'memory_max': 0,
                'network_sent_total': 0, 'network_recv_total': 0,
                'disk_read_total': 0, 'disk_write_total': 0,
                'duration_seconds': 0,
                'energy_metrics': self.energy_analyzer.calculate_metrics()
            }
        
        summary = {
            'cpu_avg': round(np.mean(self.metrics['cpu']), 2),
            'cpu_max': round(np.max(self.metrics['cpu']), 2),
            'memory_avg': round(np.mean(self.metrics['memory']), 2),
            'memory_max': round(np.max(self.metrics['memory']), 2),
            'network_sent_total': round(self.metrics['network_sent'][-1] if self.metrics['network_sent'] else 0, 3),
            'network_recv_total': round(self.metrics['network_recv'][-1] if self.metrics['network_recv'] else 0, 3),
            'disk_read_total': round(self.metrics['disk_read'][-1] if self.metrics['disk_read'] else 0, 3),
            'disk_write_total': round(self.metrics['disk_write'][-1] if self.metrics['disk_write'] else 0, 3),
            'duration_seconds': round(self.metrics['timestamps'][-1] if self.metrics['timestamps'] else 0, 2),
            'energy_metrics': self.energy_analyzer.calculate_metrics()  # NEW
        }
        
        return summary


class TrustScoreCalculator:
    """Calculate comprehensive trust scores including energy efficiency"""
    
    @staticmethod
    def calculate_trust_score(analysis_results: Dict, resource_summary: Dict, energy_metrics: Dict = None) -> Dict:
        """Calculate overall trust score with energy efficiency"""
        
        # Transparency Score (based on entropy and obfuscation)
        entropy = analysis_results.get('entropy_analysis', {}).get('entropy', 0)
        transparency_score = max(0, 100 - (entropy / 8.0) * 40)
        
        # Security Score (based on suspicious patterns and imports)
        suspicious_count = analysis_results.get('strings_analysis', {}).get('suspicious_count', 0)
        risky_imports = len(analysis_results.get('imports_exports', {}).get('suspicious_imports', []))
        url_patterns = analysis_results.get('suspicious_patterns', {}).get('url_patterns', 0)
        
        security_deductions = (suspicious_count * 5) + (risky_imports * 10) + (url_patterns * 2)
        security_score = max(0, 100 - security_deductions)
        
        # Efficiency Score (based on resource usage)
        cpu_avg = resource_summary.get('cpu_avg', 0)
        memory_avg = resource_summary.get('memory_avg', 0)
        
        efficiency_score = max(0, 100 - (cpu_avg * 0.5) - (memory_avg * 0.01))
        
        # Enhanced Sustainability Score (network, disk, AND energy)
        network_total = resource_summary.get('network_sent_total', 0) + resource_summary.get('network_recv_total', 0)
        disk_total = resource_summary.get('disk_read_total', 0) + resource_summary.get('disk_write_total', 0)
        
        # Base sustainability from network and disk
        sustainability_score = max(0, 100 - (network_total * 2) - (disk_total * 0.5))
        
        # Factor in energy efficiency if available
        if energy_metrics:
            energy_efficiency = energy_metrics.get('efficiency_score', 100)
            # Weight: 70% network/disk, 30% energy
            sustainability_score = (sustainability_score * 0.7) + (energy_efficiency * 0.3)
        
        # NEW: Reverse Engineering Quality Score
        disasm_count = analysis_results.get('disassembly', {}).get('total_instructions', 0)
        functions_count = analysis_results.get('control_flow', {}).get('functions_count', 0)
        re_quality_score = min(100, (disasm_count / 10) + (functions_count * 5))
        
        # NEW: Energy/Green Computing Score
        if energy_metrics:
            energy_score = energy_metrics.get('efficiency_score', 100)
            co2_impact = energy_metrics.get('co2_grams', 0)
            # Penalize high CO2 emissions (>1g is concerning)
            co2_penalty = min(30, co2_impact * 10)
            energy_score = max(0, energy_score - co2_penalty)
        else:
            energy_score = 50  # Neutral if not measured
        
        # Overall Score (weighted average) - now includes energy
        overall_score = round(
            (transparency_score * 0.20) +
            (security_score * 0.30) +
            (efficiency_score * 0.15) +
            (sustainability_score * 0.20) +
            (re_quality_score * 0.05) +
            (energy_score * 0.10),  # NEW: 10% weight for green computing
            2
        )
        
        # Rating
        if overall_score >= 85:
            rating = "Excellent"
        elif overall_score >= 70:
            rating = "Good"
        elif overall_score >= 55:
            rating = "Fair"
        else:
            rating = "Poor"
        
        return {
            'overall_score': round(overall_score, 2),
            'rating': rating,
            'transparency_score': round(transparency_score, 2),
            'security_score': round(security_score, 2),
            'efficiency_score': round(efficiency_score, 2),
            'sustainability_score': round(sustainability_score, 2),
            're_quality_score': round(re_quality_score, 2),
            'energy_score': round(energy_score, 2)  # NEW
        }


# ============================================================================
# ARCHIVE & ENCRYPTED FILE SCANNER
# ============================================================================

@dataclass
class ArchiveFileInfo:
    """Information about a file found in an archive"""
    filename: str
    size: int
    compressed_size: int
    is_encrypted: bool
    file_path_in_archive: str
    risk_score: float
    risk_factors: List[str]
    file_hash: Optional[str] = None
    entropy: Optional[float] = None

class ArchiveScanner:
    """
    UNIVERSAL archive scanner supporting ALL major compression formats.
    
    Supported Formats:
    - ZIP, JAR, WAR, EAR (full extraction & analysis)
    - 7-Zip (requires py7zr or external tool)
    - RAR (uses external unrar if available)
    - TAR, TAR.GZ, TAR.BZ2, TAR.XZ (full support)
    - GZIP, BZIP2, XZ, LZMA (single-file compression)
    - ISO, CAB, ARJ, LZH (detection & basic analysis)
    
    Features:
    - Magic byte detection for accurate format identification
    - Recursive scanning (archives within archives)
    - Entropy analysis for encryption detection
    - Risk/trust scoring per file and overall
    - Password-protected archive support (ZIP, 7z)
    """
    
    def __init__(self, keyword_db: 'MaliciousKeywordDatabase' = None):
        self.keyword_db = keyword_db or MaliciousKeywordDatabase()
        self.max_depth = 3  # Maximum nesting depth for archives within archives
        self.max_extract_size = 100 * 1024 * 1024  # 100MB max extraction per file
        self.scanned_files = []
        
    def scan_archive(self, archive_path: str, password: str = None) -> Dict:
        """
        Main entry point to scan an archive file.
        
        Returns:
            {
                'archive_name': str,
                'archive_type': str,
                'is_encrypted': bool,
                'total_files': int,
                'files_scanned': int,
                'files': List[ArchiveFileInfo],
                'overall_risk_score': float,
                'overall_trust_score': float,
                'risk_level': str,
                'risk_factors': List[str],
                'scan_errors': List[str]
            }
        """
        self.scanned_files = []
        scan_errors = []
        
        archive_name = os.path.basename(archive_path)
        archive_type = self._detect_archive_type(archive_path)
        
        if not archive_type:
            return {
                'error': 'Unsupported or invalid archive format',
                'archive_name': archive_name
            }
        
        try:
            # Scan based on archive type
            if archive_type == 'zip':
                files_info = self._scan_zip(archive_path, password, depth=0)
            elif archive_type == '7z':
                files_info = self._scan_7z(archive_path, password, depth=0)
            elif archive_type in ['tar', 'tar.gz', 'tar.bz2', 'tar.xz']:
                files_info = self._scan_tar(archive_path, depth=0)
            elif archive_type == 'rar':
                files_info = self._scan_rar(archive_path, password, depth=0)
            elif archive_type in ['gzip', 'bzip2', 'xz', 'lzma']:
                files_info = self._scan_single_compressed(archive_path, archive_type, depth=0)
            elif archive_type in ['iso', 'cab', 'arj', 'lzh']:
                files_info = self._scan_generic(archive_path, archive_type, depth=0)
            else:
                return {
                    'error': f'Archive type {archive_type} detection succeeded but handler not yet implemented',
                    'archive_name': archive_name,
                    'archive_type': archive_type
                }
            
        except Exception as e:
            scan_errors.append(f"Archive scan error: {str(e)}")
            files_info = []
        
        # ================================================================
        # CALCULATE OVERALL METRICS WITH ENHANCED ALGORITHM
        # ================================================================
        
        if files_info:
            risk_scores = [f.risk_score for f in files_info]
            
            # === WEIGHTED RISK CALCULATION ===
            # Not just average - use intelligent weighting
            
            max_risk_score = max(risk_scores)
            min_risk_score = min(risk_scores)
            avg_risk_score = sum(risk_scores) / len(risk_scores)
            
            # Count files by risk level
            critical_files = sum(1 for score in risk_scores if score >= 0.7)
            high_files = sum(1 for score in risk_scores if 0.5 <= score < 0.7)
            medium_files = sum(1 for score in risk_scores if 0.3 <= score < 0.5)
            low_files = sum(1 for score in risk_scores if score < 0.3)
            
            # Weighted calculation:
            # - One critical file makes whole archive risky
            # - Multiple high-risk files compound
            # - Average matters but extremes matter more
            
            overall_risk_score = avg_risk_score  # Start with average
            
            # Boost for any critical files
            if critical_files > 0:
                overall_risk_score += 0.15 * critical_files
                overall_risk_score = min(1.0, overall_risk_score)
            
            # Boost for multiple high-risk files
            if high_files >= 3:
                overall_risk_score += 0.10
            elif high_files >= 2:
                overall_risk_score += 0.05
            
            # The worst file significantly impacts overall score
            # (one very bad file in archive is dangerous)
            overall_risk_score = (overall_risk_score * 0.6) + (max_risk_score * 0.4)
            
            # If ALL files are risky, boost score
            if low_files == 0 and len(files_info) > 1:
                overall_risk_score += 0.08
            
            # If archive has many files but only a few are risky, reduce slightly
            if len(files_info) > 10 and (critical_files + high_files) == 1:
                overall_risk_score *= 0.95
            
            # Cap at 1.0
            overall_risk_score = min(1.0, overall_risk_score)
            
            # === TRUST SCORE CALCULATION ===
            # Trust is not just inverse of risk - it's more nuanced
            
            base_trust = (1.0 - overall_risk_score) * 100
            
            # Penalty for having ANY critical files
            if critical_files > 0:
                base_trust *= 0.85
            
            # Bonus for all files being low risk
            if critical_files == 0 and high_files == 0 and medium_files == 0:
                base_trust = min(100, base_trust * 1.10)
            
            # Penalty for encrypted archive (can't fully verify)
            is_encrypted_check = self._is_archive_encrypted(archive_path, archive_type)
            if is_encrypted_check:
                base_trust *= 0.90
            
            overall_trust_score = base_trust
            
            # === RISK LEVEL DETERMINATION ===
            # More sophisticated thresholds
            
            if max_risk_score >= 0.8 or overall_risk_score >= 0.6 or critical_files >= 2:
                risk_level = 'CRITICAL'
            elif max_risk_score >= 0.6 or overall_risk_score >= 0.45 or critical_files >= 1:
                risk_level = 'HIGH'
            elif max_risk_score >= 0.4 or overall_risk_score >= 0.25 or high_files >= 3:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            
            # === RISK FACTORS AGGREGATION ===
            # Categorize and prioritize risk factors
            
            threat_factors = []
            suspicious_factors = []
            info_factors = []
            
            for f in files_info:
                for factor in f.risk_factors:
                    # Categorize by keywords
                    if any(keyword in factor.lower() for keyword in ['critical', 'dangerous', 'keylog', 'injection', 'malware']):
                        threat_factors.append(factor)
                    elif any(keyword in factor.lower() for keyword in ['suspicious', 'high', 'obfuscation', 'packed']):
                        suspicious_factors.append(factor)
                    else:
                        info_factors.append(factor)
            
            # Count occurrences
            threat_counts = {}
            for factor in threat_factors:
                threat_counts[factor] = threat_counts.get(factor, 0) + 1
            
            suspicious_counts = {}
            for factor in suspicious_factors:
                suspicious_counts[factor] = suspicious_counts.get(factor, 0) + 1
            
            info_counts = {}
            for factor in info_factors:
                info_counts[factor] = info_counts.get(factor, 0) + 1
            
            # Build prioritized risk factors list
            risk_factors = []
            
            # Add summary statistics
            if critical_files > 0:
                risk_factors.append(f'{critical_files} CRITICAL threat file(s)')
            if high_files > 0:
                risk_factors.append(f'{high_files} HIGH risk file(s)')
            if medium_files > 0:
                risk_factors.append(f'{medium_files} MEDIUM risk file(s)')
            
            # Add top threats (max 3)
            top_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            for factor, count in top_threats:
                if count > 1:
                    risk_factors.append(f'{factor} (x{count})')
                else:
                    risk_factors.append(factor)
            
            # Add top suspicious (max 2)
            top_suspicious = sorted(suspicious_counts.items(), key=lambda x: x[1], reverse=True)[:2]
            for factor, count in top_suspicious:
                if count > 1:
                    risk_factors.append(f'{factor} (x{count})')
                else:
                    risk_factors.append(factor)
            
            # Limit total to 8 factors
            risk_factors = risk_factors[:8]
            
        else:
            overall_risk_score = 0.0
            overall_trust_score = 100.0
            risk_level = 'UNKNOWN'
            risk_factors = ['No files scanned']
        
        # Check if archive itself is encrypted
        is_encrypted = self._is_archive_encrypted(archive_path, archive_type)
        if is_encrypted:
            risk_factors.append('Archive is password-protected')
            # Adjust trust slightly
            if overall_trust_score > 50:
                overall_trust_score *= 0.92
        
        return {
            'archive_name': archive_name,
            'archive_type': archive_type,
            'is_encrypted': is_encrypted,
            'total_files': len(files_info),
            'files_scanned': len([f for f in files_info if f.risk_score >= 0]),
            'files': files_info,
            'overall_risk_score': round(overall_risk_score, 3),
            'overall_trust_score': round(overall_trust_score, 2),
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'scan_errors': scan_errors,
            # Enhanced scoring details
            'scoring_details': {
                'critical_files': critical_files if files_info else 0,
                'high_risk_files': high_files if files_info else 0,
                'medium_risk_files': medium_files if files_info else 0,
                'low_risk_files': low_files if files_info else 0,
                'max_file_risk': round(max_risk_score, 3) if files_info else 0,
                'min_file_risk': round(min_risk_score, 3) if files_info else 0,
                'avg_file_risk': round(avg_risk_score, 3) if files_info else 0,
                'confidence': 'HIGH' if files_info else 'UNKNOWN'
            }
        }
    
    def _detect_archive_type(self, file_path: str) -> Optional[str]:
        """Detect archive type from file extension and magic bytes - UNIVERSAL support"""
        ext = os.path.splitext(file_path)[1].lower()
        filename_lower = file_path.lower()
        
        # Check extension first (including multi-part extensions)
        if ext == '.zip' or filename_lower.endswith('.jar') or filename_lower.endswith('.war'):
            return 'zip'
        elif ext == '.7z':
            return '7z'
        elif ext == '.rar':
            return 'rar'
        elif ext == '.tar':
            return 'tar'
        elif ext in ['.tgz', '.gz'] or filename_lower.endswith('.tar.gz'):
            return 'tar.gz'
        elif ext in ['.tbz', '.tbz2', '.bz2'] or filename_lower.endswith('.tar.bz2'):
            return 'tar.bz2'
        elif ext == '.xz' or filename_lower.endswith('.tar.xz'):
            return 'tar.xz'
        elif ext == '.lzma':
            return 'lzma'
        elif ext == '.z':
            return 'compress'
        elif ext == '.iso':
            return 'iso'
        elif ext == '.cab':
            return 'cab'
        elif ext == '.arj':
            return 'arj'
        elif ext == '.lzh' or ext == '.lha':
            return 'lzh'
        
        # Check magic bytes for more accurate detection
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(32)  # Read more bytes for better detection
                
                # ZIP variants: PK (50 4B)
                if magic[:2] == b'PK':
                    return 'zip'
                
                # 7z: 37 7A BC AF 27 1C
                elif magic[:6] == b'7z\xbc\xaf\x27\x1c':
                    return '7z'
                
                # RAR v4: 52 61 72 21 1A 07 00
                elif magic[:7] == b'Rar!\x1a\x07\x00':
                    return 'rar'
                
                # RAR v5: 52 61 72 21 1A 07 01 00
                elif magic[:8] == b'Rar!\x1a\x07\x01\x00':
                    return 'rar'
                
                # GZIP: 1F 8B
                elif magic[:2] == b'\x1f\x8b':
                    return 'tar.gz' if '.tar' in filename_lower else 'gzip'
                
                # BZIP2: 42 5A 68
                elif magic[:3] == b'BZh':
                    return 'tar.bz2' if '.tar' in filename_lower else 'bzip2'
                
                # XZ: FD 37 7A 58 5A 00
                elif magic[:6] == b'\xfd7zXZ\x00':
                    return 'tar.xz' if '.tar' in filename_lower else 'xz'
                
                # LZMA: 5D 00 00
                elif magic[:3] == b'\x5d\x00\x00':
                    return 'lzma'
                
                # TAR (check for "ustar" at offset 257)
                elif len(magic) >= 262:
                    f.seek(257)
                    if f.read(5) == b'ustar':
                        return 'tar'
                
                # ISO 9660: CD001 at offset 32769
                elif magic[:5] == b'CD001':
                    return 'iso'
                
                # Cabinet (CAB): 4D 53 43 46 (MSCF)
                elif magic[:4] == b'MSCF':
                    return 'cab'
                
                # LZH/LHA: various signatures
                elif magic[2:7] == b'-lh' and magic[7:8] in [b'0', b'1', b'2', b'3', b'4', b'5', b'd']:
                    return 'lzh'
                
                # ARJ: 60 EA
                elif magic[:2] == b'\x60\xea':
                    return 'arj'
                
        except Exception as e:
            pass
        
        return None
    
    def _is_archive_encrypted(self, file_path: str, archive_type: str) -> bool:
        """Check if the archive itself is encrypted"""
        try:
            if archive_type == 'zip':
                with zipfile.ZipFile(file_path, 'r') as zf:
                    for info in zf.infolist():
                        if info.flag_bits & 0x1:  # Encryption flag
                            return True
            elif archive_type == '7z':
                with py7zr.SevenZipFile(file_path, 'r') as szf:
                    if szf.needs_password():
                        return True
        except:
            pass
        
        return False
    
    def _scan_zip(self, zip_path: str, password: str = None, depth: int = 0) -> List[ArchiveFileInfo]:
        """Scan ZIP archive recursively"""
        files_info = []
        
        if depth > self.max_depth:
            return files_info
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                pwd_bytes = password.encode() if password else None
                
                for member in zf.infolist():
                    # Skip directories
                    if member.is_dir():
                        continue
                    
                    is_encrypted = member.flag_bits & 0x1
                    
                    try:
                        # Extract and analyze
                        if member.file_size > self.max_extract_size:
                            # Too large, just record metadata
                            file_info = ArchiveFileInfo(
                                filename=member.filename,
                                size=member.file_size,
                                compressed_size=member.compress_size,
                                is_encrypted=bool(is_encrypted),
                                file_path_in_archive=member.filename,
                                risk_score=0.1,
                                risk_factors=['File too large to scan']
                            )
                        else:
                            # Extract and analyze content
                            file_data = zf.read(member, pwd=pwd_bytes)
                            file_info = self._analyze_extracted_file(
                                member.filename,
                                file_data,
                                member.file_size,
                                member.compress_size,
                                bool(is_encrypted),
                                member.filename
                            )
                            
                            # Check if extracted file is also an archive
                            if self._is_archive_filename(member.filename) and depth < self.max_depth:
                                # Save to temp and scan recursively
                                import tempfile
                                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(member.filename)[1]) as tmp:
                                    tmp.write(file_data)
                                    tmp_path = tmp.name
                                
                                try:
                                    nested_type = self._detect_archive_type(tmp_path)
                                    if nested_type:
                                        nested_files = self.scan_archive(tmp_path, password)
                                        if 'files' in nested_files:
                                            files_info.extend(nested_files['files'])
                                finally:
                                    try:
                                        os.unlink(tmp_path)
                                    except:
                                        pass
                        
                        files_info.append(file_info)
                        
                    except RuntimeError as e:
                        # Likely password protected
                        file_info = ArchiveFileInfo(
                            filename=member.filename,
                            size=member.file_size,
                            compressed_size=member.compress_size,
                            is_encrypted=True,
                            file_path_in_archive=member.filename,
                            risk_score=0.3,
                            risk_factors=['Password protected', 'Cannot scan']
                        )
                        files_info.append(file_info)
                    except Exception as e:
                        # Other errors
                        continue
        
        except Exception as e:
            pass
        
        return files_info
    
    def _scan_7z(self, archive_path: str, password: str = None, depth: int = 0) -> List[ArchiveFileInfo]:
        """Scan 7z archive - requires py7zr library or external 7z tool"""
        files_info = []
        
        if depth > self.max_depth:
            return files_info
        
        # Try py7zr first (if installed)
        try:
            import py7zr
            with py7zr.SevenZipFile(archive_path, 'r', password=password) as szf:
                for name, info in szf.list():
                    if info.is_directory:
                        continue
                    
                    try:
                        if info.uncompressed > self.max_extract_size:
                            file_info = ArchiveFileInfo(
                                filename=name,
                                size=info.uncompressed,
                                compressed_size=info.compressed,
                                is_encrypted=szf.needs_password(),
                                file_path_in_archive=name,
                                risk_score=0.1,
                                risk_factors=['File too large to scan']
                            )
                        else:
                            # Extract single file
                            import tempfile
                            with tempfile.TemporaryDirectory() as tmpdir:
                                szf.extract(tmpdir, [name])
                                extracted_path = os.path.join(tmpdir, name)
                                
                                if os.path.exists(extracted_path):
                                    with open(extracted_path, 'rb') as f:
                                        file_data = f.read()
                                    
                                    file_info = self._analyze_extracted_file(
                                        name,
                                        file_data,
                                        info.uncompressed,
                                        info.compressed,
                                        szf.needs_password(),
                                        name
                                    )
                        
                        files_info.append(file_info)
                    
                    except Exception as e:
                        continue
            
            return files_info
            
        except ImportError:
            # py7zr not installed, try external 7z tool
            pass
        except Exception as e:
            # Other errors with py7zr
            pass
        
        # Try external 7z/7za tool
        try:
            result = subprocess.run(
                ['7z', 'l', '-slt', archive_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Parse 7z output
                lines = result.stdout.split('\n')
                current_file = {}
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('Path = '):
                        if current_file and 'Path' in current_file:
                            # Save previous file
                            try:
                                file_info = ArchiveFileInfo(
                                    filename=os.path.basename(current_file.get('Path', 'unknown')),
                                    size=int(current_file.get('Size', 0)),
                                    compressed_size=int(current_file.get('Packed Size', 0)),
                                    is_encrypted=current_file.get('Encrypted', '').startswith('+'),
                                    file_path_in_archive=current_file.get('Path', ''),
                                    risk_score=0.1,
                                    risk_factors=['7z archive - cannot extract for deep scan']
                                )
                                files_info.append(file_info)
                            except:
                                pass
                        current_file = {}
                        current_file['Path'] = line.split(' = ', 1)[1]
                    elif ' = ' in line:
                        key, value = line.split(' = ', 1)
                        current_file[key] = value
                
                # Don't forget last file
                if current_file and 'Path' in current_file:
                    try:
                        file_info = ArchiveFileInfo(
                            filename=os.path.basename(current_file.get('Path', 'unknown')),
                            size=int(current_file.get('Size', 0)),
                            compressed_size=int(current_file.get('Packed Size', 0)),
                            is_encrypted=current_file.get('Encrypted', '').startswith('+'),
                            file_path_in_archive=current_file.get('Path', ''),
                            risk_score=0.1,
                            risk_factors=['7z archive - metadata only']
                        )
                        files_info.append(file_info)
                    except:
                        pass
                
                return files_info
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # 7z tool not available
            pass
        
        # Final fallback: metadata-only analysis
        if not files_info:
            try:
                stat = os.stat(archive_path)
                file_info = ArchiveFileInfo(
                    filename=os.path.basename(archive_path),
                    size=stat.st_size,
                    compressed_size=stat.st_size,
                    is_encrypted=False,
                    file_path_in_archive='<archive>',
                    risk_score=0.2,
                    risk_factors=[
                        '7z format - py7zr not installed',
                        'External 7z tool not found',
                        'Metadata-only analysis',
                        'Install py7zr or 7-Zip for full scan'
                    ]
                )
                files_info.append(file_info)
            except:
                pass
        
        return files_info
    
    def _scan_rar(self, rar_path: str, password: str = None, depth: int = 0) -> List[ArchiveFileInfo]:
        """Scan RAR archive using external tool or metadata parsing"""
        files_info = []
        
        if depth > self.max_depth:
            return files_info
        
        # Try using external unrar tool if available
        try:
            result = subprocess.run(
                ['unrar', 'l', '-v', rar_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Parse unrar output
                lines = result.stdout.split('\n')
                for line in lines:
                    # Look for file entries
                    # Format typically: filename, size, packed, ratio, date, time, attr, crc
                    if re.match(r'^\s*\d+', line):
                        parts = line.split()
                        if len(parts) >= 3:
                            filename = parts[-1]
                            try:
                                size = int(parts[0])
                                compressed = int(parts[1]) if len(parts) > 1 else size
                                
                                file_info = ArchiveFileInfo(
                                    filename=filename,
                                    size=size,
                                    compressed_size=compressed,
                                    is_encrypted=False,
                                    file_path_in_archive=filename,
                                    risk_score=0.1,
                                    risk_factors=['RAR archive - cannot extract for deep scan']
                                )
                                files_info.append(file_info)
                            except:
                                continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # unrar not available or timeout
            pass
        
        # Fallback: metadata-only analysis
        if not files_info:
            try:
                stat = os.stat(rar_path)
                file_info = ArchiveFileInfo(
                    filename=os.path.basename(rar_path),
                    size=stat.st_size,
                    compressed_size=stat.st_size,
                    is_encrypted=False,
                    file_path_in_archive='<archive>',
                    risk_score=0.15,
                    risk_factors=['RAR format - external tool needed for full scan', 'Metadata-only analysis']
                )
                files_info.append(file_info)
            except:
                pass
        
        return files_info
    
    def _scan_single_compressed(self, file_path: str, comp_type: str, depth: int = 0) -> List[ArchiveFileInfo]:
        """Scan single-file compressed formats (gzip, bzip2, xz, lzma)"""
        files_info = []
        
        if depth > self.max_depth:
            return files_info
        
        try:
            # Determine compression type and decompress
            if comp_type == 'gzip':
                with gzip.open(file_path, 'rb') as f:
                    decompressed = f.read(self.max_extract_size)
            elif comp_type == 'bzip2':
                with bz2.open(file_path, 'rb') as f:
                    decompressed = f.read(self.max_extract_size)
            elif comp_type == 'xz':
                with lzma.open(file_path, 'rb') as f:
                    decompressed = f.read(self.max_extract_size)
            elif comp_type == 'lzma':
                with lzma.open(file_path, 'rb', format=lzma.FORMAT_ALONE) as f:
                    decompressed = f.read(self.max_extract_size)
            else:
                return files_info
            
            # Get original filename (without compression extension)
            original_name = os.path.basename(file_path)
            for ext in ['.gz', '.bz2', '.xz', '.lzma', '.z']:
                if original_name.endswith(ext):
                    original_name = original_name[:-len(ext)]
                    break
            
            stat = os.stat(file_path)
            
            # Analyze decompressed content
            file_info = self._analyze_extracted_file(
                original_name,
                decompressed,
                len(decompressed),
                stat.st_size,
                False,
                original_name
            )
            
            files_info.append(file_info)
            
            # Check if decompressed data is another archive
            if depth < self.max_depth:
                # Save to temp and try to scan as archive
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False, suffix='_decompressed') as tmp:
                    tmp.write(decompressed[:100])  # Just header for detection
                    tmp_path = tmp.name
                
                try:
                    nested_type = self._detect_archive_type(tmp_path)
                    if nested_type and nested_type != comp_type:
                        # It's a nested archive, save full content and scan
                        with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{nested_type}') as tmp2:
                            tmp2.write(decompressed)
                            tmp2_path = tmp2.name
                        
                        nested_results = self.scan_archive(tmp2_path, password=None)
                        if 'files' in nested_results:
                            files_info.extend(nested_results['files'])
                        
                        try:
                            os.unlink(tmp2_path)
                        except:
                            pass
                finally:
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
        
        except Exception as e:
            # Failed to decompress, just report metadata
            try:
                stat = os.stat(file_path)
                file_info = ArchiveFileInfo(
                    filename=os.path.basename(file_path),
                    size=stat.st_size,
                    compressed_size=stat.st_size,
                    is_encrypted=False,
                    file_path_in_archive='<compressed>',
                    risk_score=0.1,
                    risk_factors=[f'{comp_type.upper()} compressed - extraction failed: {str(e)[:50]}']
                )
                files_info.append(file_info)
            except:
                pass
        
        return files_info
    
    def _scan_generic(self, file_path: str, archive_type: str, depth: int = 0) -> List[ArchiveFileInfo]:
        """Generic handler for formats requiring external tools (ISO, CAB, ARJ, LZH)"""
        files_info = []
        
        try:
            stat = os.stat(file_path)
            
            # Provide metadata-only analysis
            file_info = ArchiveFileInfo(
                filename=os.path.basename(file_path),
                size=stat.st_size,
                compressed_size=stat.st_size,
                is_encrypted=False,
                file_path_in_archive='<archive>',
                risk_score=0.2,
                risk_factors=[
                    f'{archive_type.upper()} format detected',
                    'External tools required for deep scan',
                    'Basic analysis only - consider manual inspection'
                ]
            )
            
            # Add format-specific warnings
            if archive_type == 'iso':
                file_info.risk_factors.append('ISO disc image - may contain bootable code')
            elif archive_type == 'cab':
                file_info.risk_factors.append('Windows Cabinet file - common in installers')
            elif archive_type in ['arj', 'lzh']:
                file_info.risk_factors.append('Legacy format - rare in modern use')
            
            files_info.append(file_info)
        
        except Exception as e:
            pass
        
        return files_info
    
    def _scan_tar(self, tar_path: str, depth: int = 0) -> List[ArchiveFileInfo]:
        """Scan TAR archive recursively"""
        files_info = []
        
        if depth > self.max_depth:
            return files_info
        
        try:
            with tarfile.open(tar_path, 'r:*') as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    
                    try:
                        if member.size > self.max_extract_size:
                            file_info = ArchiveFileInfo(
                                filename=member.name,
                                size=member.size,
                                compressed_size=member.size,
                                is_encrypted=False,
                                file_path_in_archive=member.name,
                                risk_score=0.1,
                                risk_factors=['File too large to scan']
                            )
                        else:
                            file_obj = tf.extractfile(member)
                            if file_obj:
                                file_data = file_obj.read()
                                
                                file_info = self._analyze_extracted_file(
                                    member.name,
                                    file_data,
                                    member.size,
                                    member.size,
                                    False,
                                    member.name
                                )
                        
                        files_info.append(file_info)
                    
                    except Exception as e:
                        continue
        
        except Exception as e:
            pass
        
        return files_info
    
    def _is_archive_filename(self, filename: str) -> bool:
        """Check if filename indicates an archive - UNIVERSAL support"""
        archive_exts = [
            '.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz', '.tgz', '.tbz', 
            '.tar.gz', '.tar.bz2', '.tar.xz', '.lzma', '.z', '.iso', '.cab', 
            '.arj', '.lzh', '.lha', '.jar', '.war', '.ear'
        ]
        filename_lower = filename.lower()
        return any(filename_lower.endswith(ext) for ext in archive_exts)
    
    def _analyze_extracted_file(self, filename: str, file_data: bytes, 
                                uncompressed_size: int, compressed_size: int,
                                is_encrypted: bool, path_in_archive: str) -> ArchiveFileInfo:
        """
        Analyze extracted file content and calculate ACCURATE risk score.
        
        Risk Scoring Algorithm:
        - Base: 0.0 (safe)
        - Maximum: 1.0 (critical)
        - Multiple weighted factors
        - Context-aware adjustments
        - False positive mitigation
        """
        risk_score = 0.0
        risk_factors = []
        threat_indicators = []  # High-confidence threats
        suspicious_indicators = []  # Medium-confidence
        informational = []  # Low-confidence / context
        
        # Calculate hash
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        # Calculate entropy
        entropy = self._calculate_entropy(file_data)
        
        # Check file extension
        file_ext = os.path.splitext(filename)[1].lower()
        filename_lower = filename.lower()
        
        # ================================================================
        # ENHANCED CATEGORIZATION
        # ================================================================
        
        # CRITICAL EXECUTABLES (Windows/DOS)
        critical_exes = ['.exe', '.dll', '.sys', '.drv', '.ocx', '.scr', '.cpl']
        
        # HIGH RISK EXECUTABLES
        high_risk_exes = ['.com', '.msi', '.msp', '.mst', '.pif']
        
        # VERY DANGEROUS SCRIPT TYPES
        dangerous_scripts = ['.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', 
                            '.hta', '.gadget', '.application', '.jar']
        
        # MODERATE RISK SCRIPTS
        moderate_scripts = ['.ps1', '.psm1', '.bat', '.cmd', '.reg']
        
        # DEVELOPMENT SCRIPTS (Lower risk if legitimate)
        dev_scripts = ['.py', '.rb', '.pl', '.php', '.lua', '.sh']
        
        # DOCUMENT MACROS
        macro_docs = ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm']
        
        # SAFE DOCUMENTS
        safe_docs = ['.txt', '.pdf', '.jpg', '.png', '.gif', '.mp3', '.mp4', 
                    '.docx', '.xlsx', '.pptx', '.csv', '.json', '.xml']
        
        # ARCHIVE FORMATS
        archive_formats = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']
        
        # ================================================================
        # FILE TYPE RISK ASSESSMENT
        # ================================================================
        
        if file_ext in critical_exes:
            risk_score += 0.35
            threat_indicators.append(f'Windows executable ({file_ext})')
            
            # Additional risk for specific types
            if file_ext in ['.scr', '.cpl']:
                risk_score += 0.10
                threat_indicators.append('High-risk executable type')
                
        elif file_ext in high_risk_exes:
            risk_score += 0.30
            threat_indicators.append(f'Installer/Package ({file_ext})')
            
        elif file_ext in dangerous_scripts:
            risk_score += 0.40  # Scripts are VERY dangerous
            threat_indicators.append(f'Dangerous script type ({file_ext})')
            
            # VBS/HTA are extremely risky
            if file_ext in ['.vbs', '.hta', '.wsh']:
                risk_score += 0.15
                threat_indicators.append('Extremely high-risk script')
                
        elif file_ext in moderate_scripts:
            risk_score += 0.25
            suspicious_indicators.append(f'Script file ({file_ext})')
            
        elif file_ext in dev_scripts:
            # Development scripts - context matters
            risk_score += 0.10
            informational.append(f'Development script ({file_ext})')
            
        elif file_ext in macro_docs:
            risk_score += 0.20
            suspicious_indicators.append(f'Macro-enabled document ({file_ext})')
            
        elif file_ext in archive_formats:
            # Nested archive
            risk_score += 0.05
            informational.append(f'Nested archive ({file_ext})')
            
        elif file_ext in safe_docs:
            # Safe file types - minimal risk
            informational.append(f'Document ({file_ext})')
            
        else:
            # Unknown extension
            if file_ext and len(file_ext) > 1:
                risk_score += 0.05
                informational.append(f'Unknown file type ({file_ext})')
            else:
                risk_score += 0.08
                suspicious_indicators.append('No file extension')
        
        # ================================================================
        # ENTROPY ANALYSIS (Encryption/Packing Detection)
        # ================================================================
        
        if entropy > 7.8:
            risk_score += 0.25
            threat_indicators.append(f'Very high entropy ({entropy:.2f}) - likely encrypted/packed')
        elif entropy > 7.5:
            risk_score += 0.18
            suspicious_indicators.append(f'High entropy ({entropy:.2f}) - possibly packed')
        elif entropy > 7.0:
            risk_score += 0.10
            informational.append(f'Elevated entropy ({entropy:.2f})')
        elif entropy < 4.0:
            # Very low entropy might indicate simple dropper
            if file_ext in critical_exes or file_ext in high_risk_exes:
                risk_score += 0.05
                suspicious_indicators.append(f'Unusually low entropy for executable ({entropy:.2f})')
            else:
                informational.append(f'Low entropy ({entropy:.2f}) - plain text/simple data')
        
        # ================================================================
        # ENCRYPTION FLAG
        # ================================================================
        
        if is_encrypted:
            risk_score += 0.20
            suspicious_indicators.append('File encrypted in archive')
        
        # ================================================================
        # FILENAME ANALYSIS (Keyword Database)
        # ================================================================
        
        is_suspicious, keyword_risk, matched_keywords = self.keyword_db.check_process_name(filename)
        if is_suspicious:
            # Scale keyword risk based on severity
            adjusted_keyword_risk = keyword_risk * 1.2  # Boost keyword importance
            risk_score += min(adjusted_keyword_risk, 0.5)  # Cap at 0.5
            
            if keyword_risk >= 0.6:  # Critical keywords
                threat_indicators.append(f'CRITICAL keywords: {", ".join(matched_keywords[:2])}')
            elif keyword_risk >= 0.4:  # High severity
                threat_indicators.append(f'Suspicious keywords: {", ".join(matched_keywords[:3])}')
            else:
                suspicious_indicators.append(f'Keywords: {", ".join(matched_keywords[:3])}')
        
        # ================================================================
        # CONTENT ANALYSIS (Pattern Detection)
        # ================================================================
        
        try:
            content_str = file_data[:20480].decode('latin-1', errors='ignore')  # First 20KB
            
            # === URLs (Command & Control potential) ===
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])+', content_str)
            url_count = len(urls)
            
            if url_count > 20:
                risk_score += 0.20
                threat_indicators.append(f'{url_count} URLs - possible C2 communication')
            elif url_count > 10:
                risk_score += 0.15
                suspicious_indicators.append(f'{url_count} URLs found')
            elif url_count > 3:
                risk_score += 0.08
                informational.append(f'{url_count} URLs')
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.cc', '.pw', '.top']
            for url in urls[:10]:  # Check first 10
                if any(tld in url.lower() for tld in suspicious_tlds):
                    risk_score += 0.10
                    suspicious_indicators.append('Suspicious TLD in URL')
                    break
            
            # === IP Addresses (Direct connection attempts) ===
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content_str)
            ip_count = len(set(ips))  # Unique IPs
            
            if ip_count > 10:
                risk_score += 0.18
                threat_indicators.append(f'{ip_count} IP addresses - hardcoded connections')
            elif ip_count > 5:
                risk_score += 0.12
                suspicious_indicators.append(f'{ip_count} IP addresses')
            elif ip_count > 2:
                risk_score += 0.06
                informational.append(f'{ip_count} IP addresses')
            
            # === Base64 Encoded Data (Obfuscation) ===
            base64_matches = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', content_str)
            
            if len(base64_matches) > 10:
                risk_score += 0.15
                suspicious_indicators.append(f'{len(base64_matches)} Base64 strings - obfuscation')
            elif len(base64_matches) > 5:
                risk_score += 0.08
                informational.append(f'{len(base64_matches)} Base64 strings')
            
            # === Dangerous Windows APIs ===
            critical_apis = [
                'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
                'NtCreateThreadEx', 'RtlCreateUserThread', 'QueueUserAPC'
            ]
            injection_apis = [
                'SetWindowsHookEx', 'SetThreadContext', 'NtSetContextThread',
                'NtQueueApcThread', 'NtWriteVirtualMemory'
            ]
            keylogging_apis = [
                'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState',
                'SetWindowsHookEx', 'RegisterHotKey'
            ]
            network_apis = [
                'URLDownloadToFile', 'InternetOpen', 'HttpSendRequest',
                'WinHttpOpen', 'socket', 'connect', 'send', 'recv'
            ]
            execution_apis = [
                'ShellExecute', 'WinExec', 'CreateProcess', 'system',
                'exec', 'eval', 'popen'
            ]
            
            critical_api_found = [api for api in critical_apis if api in content_str]
            injection_api_found = [api for api in injection_apis if api in content_str]
            keylog_api_found = [api for api in keylogging_apis if api in content_str]
            network_api_found = [api for api in network_apis if api in content_str]
            exec_api_found = [api for api in execution_apis if api in content_str]
            
            if critical_api_found:
                risk_score += 0.30
                threat_indicators.append(f'CRITICAL APIs: {", ".join(critical_api_found[:2])}')
            
            if injection_api_found:
                risk_score += 0.25
                threat_indicators.append(f'Injection APIs: {", ".join(injection_api_found[:2])}')
            
            if keylog_api_found:
                risk_score += 0.35
                threat_indicators.append(f'Keylogging APIs: {", ".join(keylog_api_found[:2])}')
            
            if network_api_found and len(network_api_found) >= 3:
                risk_score += 0.15
                suspicious_indicators.append(f'Network APIs ({len(network_api_found)})')
            
            if exec_api_found:
                risk_score += 0.18
                suspicious_indicators.append(f'Execution APIs: {", ".join(exec_api_found[:2])}')
            
            # === Registry Manipulation ===
            registry_patterns = [
                r'HKEY_CURRENT_USER.*Run',
                r'HKEY_LOCAL_MACHINE.*Run',
                r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
            ]
            
            persistence_found = False
            for pattern in registry_patterns:
                if re.search(pattern, content_str, re.IGNORECASE):
                    risk_score += 0.22
                    threat_indicators.append('Registry persistence detected')
                    persistence_found = True
                    break
            
            if not persistence_found:
                if 'HKEY_' in content_str or 'SOFTWARE\\' in content_str:
                    risk_score += 0.08
                    informational.append('Registry access')
            
            # === PowerShell Obfuscation ===
            if file_ext == '.ps1' or 'powershell' in content_str.lower():
                obfuscation_indicators = [
                    '-encodedcommand', '-enc', 'frombase64string',
                    'invoke-expression', 'iex', 'invoke-command',
                    '-windowstyle hidden', '-noprofile', '-noninteractive'
                ]
                
                obfusc_count = sum(1 for ind in obfuscation_indicators if ind.lower() in content_str.lower())
                if obfusc_count >= 3:
                    risk_score += 0.25
                    threat_indicators.append('PowerShell obfuscation detected')
                elif obfusc_count >= 1:
                    risk_score += 0.12
                    suspicious_indicators.append('PowerShell evasion techniques')
            
            # === SQL Injection Patterns ===
            sql_patterns = ['union select', 'drop table', '1=1', 'or 1=1', 'exec(@']
            sql_count = sum(1 for p in sql_patterns if p.lower() in content_str.lower())
            if sql_count >= 2:
                risk_score += 0.12
                suspicious_indicators.append('SQL injection patterns')
            
            # === Shell Commands ===
            shell_commands = ['rm -rf', 'del /f', 'format c:', 'dd if=', 'chmod 777']
            dangerous_cmd = [cmd for cmd in shell_commands if cmd.lower() in content_str.lower()]
            if dangerous_cmd:
                risk_score += 0.15
                suspicious_indicators.append(f'Dangerous commands: {", ".join(dangerous_cmd[:2])}')
        
        except Exception as e:
            # Content analysis failed - suspicious in itself
            if file_ext in critical_exes or file_ext in high_risk_exes:
                risk_score += 0.05
                informational.append('Content analysis failed (binary file)')
        
        # ================================================================
        # FILE SIZE ANALYSIS
        # ================================================================
        
        # Very small executables (likely droppers/stubs)
        if file_ext in critical_exes or file_ext in high_risk_exes:
            if uncompressed_size < 5120:  # < 5KB
                risk_score += 0.20
                threat_indicators.append(f'Tiny executable ({uncompressed_size} bytes) - likely dropper')
            elif uncompressed_size < 15360:  # < 15KB
                risk_score += 0.12
                suspicious_indicators.append(f'Small executable ({uncompressed_size} bytes)')
        
        # Very large files (potential data exfiltration or payloads)
        if uncompressed_size > 50 * 1024 * 1024:  # > 50MB
            informational.append(f'Large file ({uncompressed_size // (1024*1024)} MB)')
        
        # ================================================================
        # COMPRESSION RATIO ANALYSIS
        # ================================================================
        
        if compressed_size > 0 and uncompressed_size > 0:
            compression_ratio = compressed_size / uncompressed_size
            
            # Very low compression = already compressed/encrypted
            if compression_ratio > 0.98 and uncompressed_size > 1024:
                risk_score += 0.12
                suspicious_indicators.append(f'No compression ({compression_ratio*100:.1f}%) - pre-packed')
            elif compression_ratio > 0.95 and uncompressed_size > 5120:
                risk_score += 0.08
                informational.append(f'Low compression ({compression_ratio*100:.1f}%)')
            
            # Extremely high compression (suspicious)
            elif compression_ratio < 0.10 and uncompressed_size > 10240:
                risk_score += 0.05
                informational.append(f'Very high compression ({compression_ratio*100:.1f}%)')
        
        # ================================================================
        # PATH/FILENAME ANALYSIS
        # ================================================================
        
        # Hidden files
        if filename.startswith('.') and len(filename) > 2:
            risk_score += 0.10
            suspicious_indicators.append('Hidden file')
        
        # Suspicious paths
        suspicious_paths = ['\\temp\\', '\\tmp\\', '/tmp/', '\\appdata\\local\\temp\\']
        if any(path in path_in_archive.lower() for path in suspicious_paths):
            risk_score += 0.08
            informational.append('Temporary folder path')
        
        # Double extensions (classic obfuscation)
        if filename.count('.') >= 2:
            parts = filename.split('.')
            if len(parts) >= 3:
                # Check if second-to-last extension looks like document
                doc_exts = ['pdf', 'doc', 'xls', 'jpg', 'png', 'txt']
                if parts[-2].lower() in doc_exts:
                    risk_score += 0.25
                    threat_indicators.append(f'Double extension ({parts[-2]}.{parts[-1]}) - likely obfuscation')
        
        # Unicode/special characters in filename
        if not all(ord(c) < 128 for c in filename):
            risk_score += 0.08
            suspicious_indicators.append('Non-ASCII characters in filename')
        
        # ================================================================
        # POSITIVE INDICATORS (Risk Reduction)
        # ================================================================
        
        # Code signing indicators (if present, reduce risk)
        if b'Digital Signature' in file_data or b'CERTIFICATE' in file_data:
            risk_score = max(0, risk_score - 0.10)
            informational.append('Digital signature detected')
        
        # Legitimate software indicators
        legitimate_markers = [
            b'Microsoft Corporation', b'Adobe Systems', b'Google Inc',
            b'Copyright (c)', b'Licensed under'
        ]
        if any(marker in file_data[:5000] for marker in legitimate_markers):
            risk_score = max(0, risk_score - 0.08)
            informational.append('Legitimate software markers')
        
        # ================================================================
        # FINAL RISK SCORE CALCULATION
        # ================================================================
        
        # Cap risk score at 1.0
        risk_score = min(1.0, risk_score)
        
        # Assemble final risk factors in priority order
        final_risk_factors = []
        
        if threat_indicators:
            final_risk_factors.extend(threat_indicators)
        if suspicious_indicators:
            final_risk_factors.extend(suspicious_indicators)
        if informational:
            # Limit informational to top 3
            final_risk_factors.extend(informational[:3])
        
        if not final_risk_factors:
            final_risk_factors.append('No suspicious indicators detected')
        
        return ArchiveFileInfo(
            filename=filename,
            size=uncompressed_size,
            compressed_size=compressed_size,
            is_encrypted=is_encrypted,
            file_path_in_archive=path_in_archive,
            risk_score=risk_score,
            risk_factors=final_risk_factors,
            file_hash=file_hash,
            entropy=entropy
        )
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in frequencies.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1 if probability < 1 else 0)
        
        # Normalize to 0-8 range
        import math
        if data_len > 0:
            entropy = -sum((count / data_len) * math.log2(count / data_len) 
                          for count in frequencies.values() if count > 0)
        
        return entropy


# ============================================================================
# DIRECTORY SCANNER FOR MALICIOUS FILES
# ============================================================================

class DirectoryScanner:
    """Scan directories for suspicious and malicious files, including archives"""
    
    def __init__(self, keyword_db: 'MaliciousKeywordDatabase' = None):
        self.scan_results = []
        self.scanning = False
        self.keyword_db = keyword_db or MaliciousKeywordDatabase()
        self.archive_scanner = ArchiveScanner(self.keyword_db)
        
    def scan_directory(self, directory: str, max_files: int = 100) -> List[Dict]:
        """Scan a directory for suspicious files"""
        self.scan_results = []
        self.scanning = True
        
        try:
            file_count = 0
            for root, dirs, files in os.walk(directory):
                if file_count >= max_files:
                    break
                
                for filename in files:
                    if file_count >= max_files:
                        break
                    
                    file_path = os.path.join(root, filename)
                    
                    try:
                        file_info = self._analyze_file(file_path)
                        if file_info:
                            self.scan_results.append(file_info)
                            file_count += 1
                    except Exception as e:
                        continue
            
        except Exception as e:
            pass
        
        self.scanning = False
        
        # Sort by risk score
        self.scan_results.sort(key=lambda x: x['risk_score'], reverse=True)
        return self.scan_results
    
    def _analyze_file(self, file_path: str) -> Optional[Dict]:
        """Analyze a single file for suspicious behavior, including deep archive scanning"""
        try:
            # Get file info
            stat = os.stat(file_path)
            filename = os.path.basename(file_path)
            file_ext = os.path.splitext(filename)[1].lower()
            
            # Skip very large files (> 50MB) for performance
            if stat.st_size > 50 * 1024 * 1024:
                return None
            
            risk_score = 0.0
            risk_factors = []
            archive_details = None
            
            # Check file extension
            executable_exts = ['.exe', '.dll', '.bat', '.cmd', '.vbs', '.ps1', '.scr', '.com']
            script_exts = ['.py', '.js', '.jar', '.sh', '.pl']
            archive_exts = [
                '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.tbz', '.xz', 
                '.lzma', '.z', '.iso', '.cab', '.arj', '.lzh', '.lha', '.war', '.ear'
            ]
            
            # ENHANCED: Deep scan ALL archive types
            if file_ext in archive_exts or any(file_path.lower().endswith(ext) for ext in ['.tar.gz', '.tar.bz2', '.tar.xz', '.tar.lzma']):
                try:
                    archive_scan = self.archive_scanner.scan_archive(file_path)
                    
                    if 'error' not in archive_scan:
                        # Use archive scan results
                        risk_score = archive_scan['overall_risk_score']
                        
                        risk_factors.append(f"Archive: {archive_scan['total_files']} files")
                        if archive_scan['is_encrypted']:
                            risk_factors.append('Encrypted archive')
                        
                        risk_factors.extend(archive_scan['risk_factors'][:3])
                        
                        # Store archive details
                        archive_details = {
                            'is_archive': True,
                            'archive_type': archive_scan['archive_type'],
                            'total_files': archive_scan['total_files'],
                            'files_scanned': archive_scan['files_scanned'],
                            'trust_score': archive_scan['overall_trust_score'],
                            'risk_level': archive_scan['risk_level'],
                            'detailed_files': [
                                {
                                    'filename': f.filename,
                                    'size': f.size,
                                    'risk_score': f.risk_score,
                                    'risk_factors': f.risk_factors,
                                    'is_encrypted': f.is_encrypted,
                                    'entropy': f.entropy
                                }
                                for f in archive_scan['files'][:20]  # Top 20 files
                            ]
                        }
                        
                        # Archive scanning replaces standard file analysis
                        return {
                            'filename': filename,
                            'path': file_path,
                            'size_mb': round(stat.st_size / (1024 * 1024), 2),
                            'extension': file_ext,
                            'entropy': 0.0,  # Archive entropy not meaningful
                            'risk_score': round(risk_score, 2),
                            'risk_level': archive_scan['risk_level'],
                            'risk_factors': ', '.join(risk_factors),
                            'modified': time.strftime('%Y-%m-%d', time.localtime(stat.st_mtime)),
                            'archive_details': archive_details
                        }
                    else:
                        # Archive scan failed, fall back to standard analysis
                        risk_score += 0.10
                        risk_factors.append(f"Archive (scan failed: {archive_scan.get('error', 'unknown')})")
                
                except Exception as e:
                    risk_score += 0.10
                    risk_factors.append(f'Archive (scan error)')
            
            # Read file for analysis (first 10KB)
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read(10240)  # Read first 10KB
            except:
                return None
            
            # Calculate entropy (high entropy = potentially encrypted/packed)
            entropy = self._calculate_entropy(file_data)
            
            # Suspicious file extensions
            if file_ext in executable_exts:
                risk_score += 0.2
                risk_factors.append('Executable')
                
                # High entropy in executable = packed/encrypted
                if entropy > 7.5:
                    risk_score += 0.3
                    risk_factors.append('Packed/Encrypted')
            
            elif file_ext in script_exts:
                risk_score += 0.1
                risk_factors.append('Script File')
            
            # Check filename with keyword database
            is_suspicious, keyword_risk, matched_keywords = self.keyword_db.check_process_name(filename)
            if is_suspicious:
                risk_score += keyword_risk
                keyword_summary = ', '.join(matched_keywords[:3])
                risk_factors.append(f'Suspicious name: {keyword_summary}')
            
            # Check for suspicious strings
            try:
                content_str = file_data.decode('latin-1', errors='ignore')
                
                # Use keyword database instead of hardcoded list
                keyword_count = 0
                for keyword in ['password', 'credential', 'encrypt', 'decrypt', 'payload', 
                               'shellcode', 'exploit', 'inject']:
                    if keyword in content_str.lower():
                        keyword_count += 1
                
                if keyword_count >= 3:
                    risk_score += 0.4
                    risk_factors.append(f'{keyword_count} Suspicious Keywords')
                elif keyword_count >= 1:
                    risk_score += 0.2
                    risk_factors.append(f'{keyword_count} Suspicious Keywords')
                
                # Check for URLs
                url_count = len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])+', content_str))
                if url_count > 5:
                    risk_score += 0.2
                    risk_factors.append(f'{url_count} URLs')
                
                # Check for IP addresses
                ip_count = len(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content_str))
                if ip_count > 3:
                    risk_score += 0.15
                    risk_factors.append(f'{ip_count} IPs')
                
                # Check for base64 encoded data
                base64_count = len(re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', content_str))
                if base64_count > 5:
                    risk_score += 0.1
                    risk_factors.append('Encoded Data')
                
                # Check for registry keys
                if 'HKEY_' in content_str or 'SOFTWARE\\' in content_str:
                    risk_score += 0.1
                    risk_factors.append('Registry Access')
                
                # Check for dangerous API calls
                dangerous_apis = [
                    'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
                    'SetWindowsHookEx', 'GetAsyncKeyState', 'URLDownloadToFile'
                ]
                api_count = sum(1 for api in dangerous_apis if api in content_str)
                if api_count > 0:
                    risk_score += 0.3
                    risk_factors.append(f'{api_count} Dangerous APIs')
                
            except:
                pass
            
            # Check file location
            file_path_lower = file_path.lower()
            suspicious_locations = [
                'temp', 'tmp', 'appdata\\local\\temp', 'downloads',
                'recycle', 'startup', 'autorun'
            ]
            
            if any(loc in file_path_lower for loc in suspicious_locations):
                risk_score += 0.15
                risk_factors.append('Suspicious Location')
            
            # Hidden or system files
            if filename.startswith('.'):
                risk_score += 0.1
                risk_factors.append('Hidden File')
            
            # Very small executables (potential droppers)
            if file_ext in executable_exts and stat.st_size < 10240:  # < 10KB
                risk_score += 0.2
                risk_factors.append('Tiny Executable')
            
            # Determine risk level
            risk_score = min(1.0, risk_score)  # Cap at 1.0
            
            if risk_score >= 0.7:
                risk_level = 'CRITICAL'
                risk_color = '#ff0000'
            elif risk_score >= 0.5:
                risk_level = 'HIGH'
                risk_color = '#ff6600'
            elif risk_score >= 0.3:
                risk_level = 'MEDIUM'
                risk_color = '#ffaa00'
            elif risk_score >= 0.1:
                risk_level = 'LOW'
                risk_color = '#ffcc00'
            else:
                risk_level = 'SAFE'
                risk_color = '#00aa00'
            
            return {
                'filename': filename[:40],
                'path': file_path[:60],
                'size': stat.st_size,
                'size_mb': round(stat.st_size / (1024 * 1024), 3),
                'extension': file_ext,
                'entropy': round(entropy, 2),
                'risk_score': round(risk_score, 2),
                'risk_level': risk_level,
                'risk_color': risk_color,
                'risk_factors': ', '.join(risk_factors) if risk_factors else 'None',
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
            }
            
        except Exception as e:
            return None
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                freq = count / data_len
                entropy -= freq * np.log2(freq)
        
        return entropy


# ============================================================================
# ENHANCED GUI WITH REVERSE ENGINEERING TABS
# ============================================================================

class TransparencyAnalyzerGUI:
    """Enhanced GUI with reverse engineering capabilities"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("📐 PRISM")
        self.root.geometry("1600x1000")
        
        self.engine = ReverseEngineeringEngine()
        self.monitor = ResourceMonitor()
        self.scanner = DirectoryScanner()
        self.analysis_results = None
        self.current_file = None
        self.process_update_job = None
        self.performance_mode = False  # Performance mode to reduce features
        
        # Initialize metrics tracking
        self.metrics_history = {
            'timestamps': [],
            'cpu': [],
            'memory': [],
            'network_sent': [],
            'network_recv': [],
            'disk_read': [],
            'disk_write': []
        }
        self.metrics_start_time = time.time()
        
        self.setup_ui()
        # Don't start process monitoring immediately - wait for user to switch to that tab
        # self.start_process_monitoring()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Title
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        title_frame.pack(fill='x')
        title_frame.pack_propagate(False)
        
        tk.Label(
            title_frame,
            text="🔬 Enhanced Software Transparency Analyzer",
            font=('Arial', 20, 'bold'),
            fg='white',
            bg='#2c3e50'
        ).pack(pady=10)
        
        tk.Label(
            title_frame,
            text="Complete Reverse Engineering • Binary Analysis • Trust Scoring • Resource Monitoring",
            font=('Arial', 10),
            fg='#ecf0f1',
            bg='#2c3e50'
        ).pack()
        
        # Control Panel
        control_frame = tk.Frame(self.root, bg='#34495e', height=60)
        control_frame.pack(fill='x')
        control_frame.pack_propagate(False)
        
        btn_style = {'bg': '#3498db', 'fg': 'white', 'font': ('Arial', 10, 'bold'), 
                    'padx': 15, 'pady': 8, 'relief': 'raised', 'bd': 2}
        
        tk.Button(control_frame, text="📂 Load Binary", command=self.load_file, **btn_style).pack(side='left', padx=10, pady=10)
        tk.Button(control_frame, text="🔬 Analyze", command=self.perform_analysis, **btn_style).pack(side='left', padx=10, pady=10)
        tk.Button(control_frame, text="📊 Generate Report", command=self.generate_report, **btn_style).pack(side='left', padx=10, pady=10)
        tk.Button(control_frame, text="💾 Export Data", command=self.export_data, **btn_style).pack(side='left', padx=10, pady=10)
        
        self.status_label = tk.Label(control_frame, text="Ready", font=('Arial', 10), fg='#2ecc71', bg='#34495e')
        self.status_label.pack(side='right', padx=20)
        
        # ALWAYS VISIBLE RESOURCE METRICS PANEL AT BOTTOM
        self.create_live_metrics_panel()
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Bind tab change event to start monitoring only when Process Monitor tab is active
        self.notebook.bind('<<NotebookTabChanged>>', self.on_tab_changed)
        
        # Create tabs
        self.create_overview_tab()
        self.create_disassembly_tab()
        self.create_control_flow_tab()
        self.create_analysis_tab()
        self.create_process_monitor_tab()  # NEW
        self.create_directory_scanner_tab()  # NEW
        self.create_metrics_tab()
        self.create_energy_tab()  # NEW: Green Computing
        self.create_scores_tab()
        
    def create_live_metrics_panel(self):
        """Create always-visible live resource metrics panel at bottom"""
        metrics_panel = tk.Frame(self.root, bg='#1e1e1e', relief='sunken', bd=2, height=80)
        metrics_panel.pack(side='bottom', fill='x', padx=5, pady=5)
        metrics_panel.pack_propagate(False)
        
        tk.Label(
            metrics_panel,
            text="📊 LIVE SYSTEM METRICS",
            font=('Arial', 10, 'bold'),
            fg='#00ff00',
            bg='#1e1e1e'
        ).pack(side='left', padx=20)
        
        # CPU Metric
        cpu_frame = tk.Frame(metrics_panel, bg='#2d2d2d', relief='raised', bd=2)
        cpu_frame.pack(side='left', padx=10, pady=10, fill='y')
        
        tk.Label(
            cpu_frame,
            text="CPU",
            font=('Arial', 8),
            fg='#888888',
            bg='#2d2d2d'
        ).pack(pady=2)
        
        self.live_cpu_label = tk.Label(
            cpu_frame,
            text="0%",
            font=('Arial', 16, 'bold'),
            fg='#00ffff',
            bg='#2d2d2d'
        )
        self.live_cpu_label.pack(pady=2, padx=10)
        
        # Memory Metric
        mem_frame = tk.Frame(metrics_panel, bg='#2d2d2d', relief='raised', bd=2)
        mem_frame.pack(side='left', padx=10, pady=10, fill='y')
        
        tk.Label(
            mem_frame,
            text="MEMORY",
            font=('Arial', 8),
            fg='#888888',
            bg='#2d2d2d'
        ).pack(pady=2)
        
        self.live_mem_label = tk.Label(
            mem_frame,
            text="0%",
            font=('Arial', 16, 'bold'),
            fg='#00ff00',
            bg='#2d2d2d'
        )
        self.live_mem_label.pack(pady=2, padx=10)
        
        # Network Metric
        net_frame = tk.Frame(metrics_panel, bg='#2d2d2d', relief='raised', bd=2)
        net_frame.pack(side='left', padx=10, pady=10, fill='y')
        
        tk.Label(
            net_frame,
            text="NETWORK",
            font=('Arial', 8),
            fg='#888888',
            bg='#2d2d2d'
        ).pack(pady=2)
        
        self.live_net_label = tk.Label(
            net_frame,
            text="0 KB/s",
            font=('Arial', 12, 'bold'),
            fg='#ffaa00',
            bg='#2d2d2d'
        )
        self.live_net_label.pack(pady=2, padx=10)
        
        # Disk Metric
        disk_frame = tk.Frame(metrics_panel, bg='#2d2d2d', relief='raised', bd=2)
        disk_frame.pack(side='left', padx=10, pady=10, fill='y')
        
        tk.Label(
            disk_frame,
            text="DISK",
            font=('Arial', 8),
            fg='#888888',
            bg='#2d2d2d'
        ).pack(pady=2)
        
        self.live_disk_label = tk.Label(
            disk_frame,
            text="0 MB/s",
            font=('Arial', 12, 'bold'),
            fg='#ff00ff',
            bg='#2d2d2d'
        )
        self.live_disk_label.pack(pady=2, padx=10)
        
        # Processes Count
        proc_frame = tk.Frame(metrics_panel, bg='#2d2d2d', relief='raised', bd=2)
        proc_frame.pack(side='left', padx=10, pady=10, fill='y')
        
        tk.Label(
            proc_frame,
            text="PROCESSES",
            font=('Arial', 8),
            fg='#888888',
            bg='#2d2d2d'
        ).pack(pady=2)
        
        self.live_proc_label = tk.Label(
            proc_frame,
            text="0",
            font=('Arial', 16, 'bold'),
            fg='#ffffff',
            bg='#2d2d2d'
        )
        self.live_proc_label.pack(pady=2, padx=10)
        
        # Start updating live metrics
        self.update_live_metrics()
    
    def update_live_metrics(self):
        """Update live metrics display - runs continuously"""
        try:
            # Get current system metrics
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory().percent
            
            # Store in history for graphs (keep last 60 seconds)
            current_time = time.time() - self.metrics_start_time
            self.metrics_history['timestamps'].append(current_time)
            self.metrics_history['cpu'].append(cpu)
            self.metrics_history['memory'].append(mem)
            
            # Keep only last 60 data points (60 seconds of data)
            max_points = 60
            if len(self.metrics_history['timestamps']) > max_points:
                for key in self.metrics_history:
                    self.metrics_history[key] = self.metrics_history[key][-max_points:]
            
            # Network speed
            try:
                net_io = psutil.net_io_counters()
                if hasattr(self, '_last_net_io'):
                    sent_rate = (net_io.bytes_sent - self._last_net_io.bytes_sent) / 1024  # KB/s
                    recv_rate = (net_io.bytes_recv - self._last_net_io.bytes_recv) / 1024  # KB/s
                    total_rate = sent_rate + recv_rate
                    
                    # Store in history
                    self.metrics_history['network_sent'].append(sent_rate)
                    self.metrics_history['network_recv'].append(recv_rate)
                    
                    # Keep only last 60
                    if len(self.metrics_history['network_sent']) > max_points:
                        self.metrics_history['network_sent'] = self.metrics_history['network_sent'][-max_points:]
                        self.metrics_history['network_recv'] = self.metrics_history['network_recv'][-max_points:]
                    
                    if total_rate < 1024:
                        net_text = f"{total_rate:.1f} KB/s"
                    else:
                        net_text = f"{total_rate/1024:.1f} MB/s"
                else:
                    net_text = "0 KB/s"
                    self.metrics_history['network_sent'].append(0)
                    self.metrics_history['network_recv'].append(0)
                
                self._last_net_io = net_io
            except:
                net_text = "N/A"
                self.metrics_history['network_sent'].append(0)
                self.metrics_history['network_recv'].append(0)
            
            # Disk I/O
            try:
                disk_io = psutil.disk_io_counters()
                if hasattr(self, '_last_disk_io'):
                    read_rate = (disk_io.read_bytes - self._last_disk_io.read_bytes) / (1024 * 1024)  # MB/s
                    write_rate = (disk_io.write_bytes - self._last_disk_io.write_bytes) / (1024 * 1024)  # MB/s
                    total_rate = read_rate + write_rate
                    disk_text = f"{total_rate:.2f} MB/s"
                    
                    # Store in history
                    self.metrics_history['disk_read'].append(read_rate)
                    self.metrics_history['disk_write'].append(write_rate)
                    
                    # Keep only last 60
                    if len(self.metrics_history['disk_read']) > max_points:
                        self.metrics_history['disk_read'] = self.metrics_history['disk_read'][-max_points:]
                        self.metrics_history['disk_write'] = self.metrics_history['disk_write'][-max_points:]
                else:
                    disk_text = "0 MB/s"
                    self.metrics_history['disk_read'].append(0)
                    self.metrics_history['disk_write'].append(0)
                
                self._last_disk_io = disk_io
            except:
                disk_text = "N/A"
                self.metrics_history['disk_read'].append(0)
                self.metrics_history['disk_write'].append(0)
            
            # Process count
            proc_count = len(psutil.pids())
            
            # Update labels
            self.live_cpu_label.config(text=f"{cpu:.1f}%")
            self.live_mem_label.config(text=f"{mem:.1f}%")
            self.live_net_label.config(text=net_text)
            self.live_disk_label.config(text=disk_text)
            self.live_proc_label.config(text=str(proc_count))
            
            # Color coding for CPU
            if cpu > 80:
                self.live_cpu_label.config(fg='#ff0000')  # Red
            elif cpu > 50:
                self.live_cpu_label.config(fg='#ffaa00')  # Orange
            else:
                self.live_cpu_label.config(fg='#00ffff')  # Cyan
            
            # Color coding for Memory
            if mem > 90:
                self.live_mem_label.config(fg='#ff0000')  # Red
            elif mem > 70:
                self.live_mem_label.config(fg='#ffaa00')  # Orange
            else:
                self.live_mem_label.config(fg='#00ff00')  # Green
                
        except Exception as e:
            print(f"Error updating live metrics: {e}")
        
        # Update every 2 seconds for better performance (was 1 second)
        self.root.after(2000, self.update_live_metrics)
    
    def update_metrics_graphs(self):
        """Update the live metrics graphs"""
        try:
            if not self.metrics_auto_update.get():
                # Skip update if auto-update is disabled
                self.root.after(1000, self.update_metrics_graphs)
                return
            
            # Only update if we have data
            if len(self.metrics_history['timestamps']) > 0:
                timestamps = self.metrics_history['timestamps']
                
                # Clear all axes
                self.ax_cpu.clear()
                self.ax_mem.clear()
                self.ax_net.clear()
                self.ax_disk.clear()
                
                # CPU Usage Graph
                self.ax_cpu.plot(timestamps, self.metrics_history['cpu'], 
                                color='#00ffff', linewidth=2, label='CPU %')
                self.ax_cpu.fill_between(timestamps, self.metrics_history['cpu'], 
                                        alpha=0.3, color='#00ffff')
                self.ax_cpu.set_ylabel('Usage (%)', color='white', fontsize=10)
                self.ax_cpu.set_xlabel('Time (seconds)', color='white', fontsize=10)
                self.ax_cpu.set_title('CPU Usage (%)', color='white', fontweight='bold', fontsize=12)
                self.ax_cpu.set_ylim(0, 100)
                self.ax_cpu.legend(loc='upper right', fontsize=9)
                
                # Memory Usage Graph
                self.ax_mem.plot(timestamps, self.metrics_history['memory'], 
                                color='#00ff00', linewidth=2, label='Memory %')
                self.ax_mem.fill_between(timestamps, self.metrics_history['memory'], 
                                        alpha=0.3, color='#00ff00')
                self.ax_mem.set_ylabel('Usage (%)', color='white', fontsize=10)
                self.ax_mem.set_xlabel('Time (seconds)', color='white', fontsize=10)
                self.ax_mem.set_title('Memory Usage (%)', color='white', fontweight='bold', fontsize=12)
                self.ax_mem.set_ylim(0, 100)
                self.ax_mem.legend(loc='upper right', fontsize=9)
                
                # Network Activity Graph
                if len(self.metrics_history['network_sent']) > 0:
                    self.ax_net.plot(timestamps[-len(self.metrics_history['network_sent']):], 
                                    self.metrics_history['network_sent'], 
                                    color='#ff6600', linewidth=2, label='Sent')
                    self.ax_net.plot(timestamps[-len(self.metrics_history['network_recv']):], 
                                    self.metrics_history['network_recv'], 
                                    color='#ffaa00', linewidth=2, label='Received')
                    self.ax_net.set_ylabel('Speed (KB/s)', color='white', fontsize=10)
                    self.ax_net.set_xlabel('Time (seconds)', color='white', fontsize=10)
                    self.ax_net.set_title('Network Activity (KB/s)', color='white', fontweight='bold', fontsize=12)
                    self.ax_net.legend(loc='upper right', fontsize=9)
                
                # Disk I/O Graph
                if len(self.metrics_history['disk_read']) > 0:
                    self.ax_disk.plot(timestamps[-len(self.metrics_history['disk_read']):], 
                                     self.metrics_history['disk_read'], 
                                     color='#ff00ff', linewidth=2, label='Read')
                    self.ax_disk.plot(timestamps[-len(self.metrics_history['disk_write']):], 
                                     self.metrics_history['disk_write'], 
                                     color='#ff66ff', linewidth=2, label='Write')
                    self.ax_disk.set_ylabel('Speed (MB/s)', color='white', fontsize=10)
                    self.ax_disk.set_xlabel('Time (seconds)', color='white', fontsize=10)
                    self.ax_disk.set_title('Disk I/O (MB/s)', color='white', fontweight='bold', fontsize=12)
                    self.ax_disk.legend(loc='upper right', fontsize=9)
                
                # Apply dark theme to all axes
                for ax in [self.ax_cpu, self.ax_mem, self.ax_net, self.ax_disk]:
                    ax.set_facecolor('#2d2d2d')
                    ax.tick_params(colors='white', labelsize=9)
                    ax.spines['bottom'].set_color('white')
                    ax.spines['left'].set_color('white')
                    ax.spines['top'].set_color('#2d2d2d')
                    ax.spines['right'].set_color('#2d2d2d')
                    ax.grid(True, alpha=0.2, color='white')
                
                self.metrics_fig.tight_layout(pad=3.0)
                self.metrics_canvas.draw()
                
                # Update duration label
                duration = timestamps[-1] if timestamps else 0
                self.metrics_duration_label.config(text=f"Duration: {int(duration)}s")
                
        except Exception as e:
            print(f"Error updating metrics graphs: {e}")
        
        # Update every 2 seconds (was 1 second for better performance)
        self.root.after(2000, self.update_metrics_graphs)
    
    def clear_metrics_history(self):
        """Clear metrics history and restart"""
        self.metrics_history = {
            'timestamps': [],
            'cpu': [],
            'memory': [],
            'network_sent': [],
            'network_recv': [],
            'disk_read': [],
            'disk_write': []
        }
        self.metrics_start_time = time.time()
        self.metrics_duration_label.config(text="Duration: 0s")
        
        # Clear graphs
        for ax in [self.ax_cpu, self.ax_mem, self.ax_net, self.ax_disk]:
            ax.clear()
        self.metrics_canvas.draw()
    
    def create_overview_tab(self):
        """Create overview tab"""
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text='📊 Overview')
        
        self.overview_text = scrolledtext.ScrolledText(
            frame, font=('Consolas', 10), bg='#1e1e1e', fg='#00ff00',
            insertbackground='white', wrap='word'
        )
        self.overview_text.pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_disassembly_tab(self):
        """Create disassembly tab"""
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text='⚙️ Disassembly')
        
        tk.Label(frame, text="Disassembled Instructions", font=('Arial', 12, 'bold')).pack(pady=5)
        
        self.disasm_text = scrolledtext.ScrolledText(
            frame, font=('Consolas', 9), bg='#1e1e1e', fg='#00ffff',
            insertbackground='white', wrap='none'
        )
        self.disasm_text.pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_control_flow_tab(self):
        """Create control flow tab"""
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text='🔀 Control Flow')
        
        tk.Label(frame, text="Control Flow Analysis & Functions", font=('Arial', 12, 'bold')).pack(pady=5)
        
        self.cfg_text = scrolledtext.ScrolledText(
            frame, font=('Consolas', 10), bg='#1e1e1e', fg='#00ff00',
            insertbackground='white', wrap='word'
        )
        self.cfg_text.pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_analysis_tab(self):
        """Create detailed analysis tab with trust scores"""
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text='🔍 Detailed Analysis')
        
        # Create split view - Trust Scores on top, Details below
        
        # Top section: Trust Scores Summary
        trust_frame = tk.Frame(frame, bg='#2d2d2d', relief='ridge', bd=3)
        trust_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(
            trust_frame,
            text="🏆 TRUST SCORE BREAKDOWN",
            font=('Arial', 14, 'bold'),
            fg='#00ff00',
            bg='#2d2d2d'
        ).pack(pady=10)
        
        # Trust score display area
        self.trust_breakdown_frame = tk.Frame(trust_frame, bg='#2d2d2d')
        self.trust_breakdown_frame.pack(fill='x', padx=20, pady=10)
        
        # Placeholder labels for trust scores
        self.overall_score_label = tk.Label(
            self.trust_breakdown_frame,
            text="Overall Score: -- / 100",
            font=('Arial', 16, 'bold'),
            fg='#ffffff',
            bg='#2d2d2d'
        )
        self.overall_score_label.pack(pady=5)
        
        self.rating_label = tk.Label(
            self.trust_breakdown_frame,
            text="Rating: --",
            font=('Arial', 12, 'bold'),
            fg='#ffaa00',
            bg='#2d2d2d'
        )
        self.rating_label.pack(pady=5)
        
        # Individual scores grid
        scores_grid = tk.Frame(self.trust_breakdown_frame, bg='#2d2d2d')
        scores_grid.pack(pady=10)
        
        self.score_labels = {}
        score_names = [
            ('transparency', 'Transparency', '#3498db'),
            ('security', 'Security', '#e74c3c'),
            ('efficiency', 'Efficiency', '#2ecc71'),
            ('sustainability', 'Sustainability', '#f39c12'),
            ('re_quality', 'RE Quality', '#9b59b6'),
            ('energy', 'Energy/Green', '#27ae60')  # NEW
        ]
        
        for i, (key, name, color) in enumerate(score_names):
            row = i // 3
            col = i % 3
            
            score_frame = tk.Frame(scores_grid, bg='#1e1e1e', relief='raised', bd=2, width=200, height=80)
            score_frame.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
            score_frame.pack_propagate(False)
            
            tk.Label(
                score_frame,
                text=name,
                font=('Arial', 10, 'bold'),
                fg=color,
                bg='#1e1e1e'
            ).pack(pady=5)
            
            score_label = tk.Label(
                score_frame,
                text="-- / 100",
                font=('Arial', 14, 'bold'),
                fg='#ffffff',
                bg='#1e1e1e'
            )
            score_label.pack(pady=5)
            
            self.score_labels[key] = score_label
        
        # Separator
        ttk.Separator(frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Bottom section: Detailed Analysis Text
        detail_label = tk.Label(
            frame,
            text="📊 Detailed Analysis Results",
            font=('Arial', 12, 'bold'),
            bg='#f0f0f0'
        )
        detail_label.pack(fill='x', padx=5, pady=5)
        
        self.analysis_text = scrolledtext.ScrolledText(
            frame, 
            font=('Consolas', 10), 
            wrap='word',
            bg='#ffffff',
            fg='#000000'
        )
        self.analysis_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def create_process_monitor_tab(self):
        """Create process monitoring tab"""
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text='⚡ Process Monitor')
        
        # Control panel
        control_frame = tk.Frame(frame, bg='#2d2d2d', height=50)
        control_frame.pack(fill='x', padx=5, pady=5)
        control_frame.pack_propagate(False)
        
        tk.Label(
            control_frame,
            text="🔴 LIVE Process Monitoring",
            font=('Arial', 12, 'bold'),
            fg='#ff0000',
            bg='#2d2d2d'
        ).pack(side='left', padx=10)
        
        self.process_count_label = tk.Label(
            control_frame,
            text="Processes: 0",
            font=('Arial', 10),
            fg='#00ff00',
            bg='#2d2d2d'
        )
        self.process_count_label.pack(side='left', padx=20)
        
        self.high_risk_label = tk.Label(
            control_frame,
            text="High Risk: 0",
            font=('Arial', 10),
            fg='#ff0000',
            bg='#2d2d2d'
        )
        self.high_risk_label.pack(side='left', padx=20)
        
        tk.Button(
            control_frame,
            text="🔄 Refresh",
            command=self.refresh_processes,
            bg='#0066cc',
            fg='white',
            font=('Arial', 9, 'bold'),
            padx=10,
            pady=5
        ).pack(side='right', padx=10)
        
        self.monitor_running = tk.BooleanVar(value=True)
        self.pause_monitor_btn = tk.Checkbutton(
            control_frame,
            text="Auto-Refresh",
            variable=self.monitor_running,
            command=self.toggle_monitoring,
            bg='#2d2d2d',
            fg='white',
            selectcolor='#0066cc',
            font=('Arial', 9, 'bold')
        )
        self.pause_monitor_btn.pack(side='right', padx=10)
        
        # Filter frame
        filter_frame = tk.Frame(frame, bg='#2d2d2d')
        filter_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(
            filter_frame,
            text="Filter:",
            font=('Arial', 9),
            fg='white',
            bg='#2d2d2d'
        ).pack(side='left', padx=5)
        
        self.process_filter_var = tk.StringVar(value='all')
        
        for text, value in [('All', 'all'), ('High Risk', 'high'), ('Critical', 'critical')]:
            tk.Radiobutton(
                filter_frame,
                text=text,
                variable=self.process_filter_var,
                value=value,
                command=self.refresh_processes,
                bg='#2d2d2d',
                fg='white',
                selectcolor='#0066cc',
                font=('Arial', 9)
            ).pack(side='left', padx=10)
        
        # Treeview for processes
        tree_frame = tk.Frame(frame)
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Scrollbars
        vsb = tk.Scrollbar(tree_frame, orient='vertical')
        hsb = tk.Scrollbar(tree_frame, orient='horizontal')
        
        # Create treeview
        columns = ('PID', 'Name', 'CPU%', 'MEM%', 'Risk', 'Level', 'Factors', 'User')
        self.process_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show='headings',
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )
        
        vsb.config(command=self.process_tree.yview)
        hsb.config(command=self.process_tree.xview)
        
        # Configure columns
        self.process_tree.heading('PID', text='PID')
        self.process_tree.heading('Name', text='Process Name')
        self.process_tree.heading('CPU%', text='CPU %')
        self.process_tree.heading('MEM%', text='MEM %')
        self.process_tree.heading('Risk', text='Risk Score')
        self.process_tree.heading('Level', text='Risk Level')
        self.process_tree.heading('Factors', text='Risk Factors')
        self.process_tree.heading('User', text='User')
        
        self.process_tree.column('PID', width=60, anchor='center')
        self.process_tree.column('Name', width=200)
        self.process_tree.column('CPU%', width=70, anchor='center')
        self.process_tree.column('MEM%', width=70, anchor='center')
        self.process_tree.column('Risk', width=80, anchor='center')
        self.process_tree.column('Level', width=80, anchor='center')
        self.process_tree.column('Factors', width=300)
        self.process_tree.column('User', width=120)
        
        # Configure tags for colors
        self.process_tree.tag_configure('critical', background='#ffcccc')
        self.process_tree.tag_configure('high', background='#ffe0cc')
        self.process_tree.tag_configure('medium', background='#fff5cc')
        self.process_tree.tag_configure('low', background='#f0f0f0')
        
        # Pack treeview
        self.process_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
    
    def create_directory_scanner_tab(self):
        """Create directory scanner tab"""
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text='🗂️ Directory Scanner')
        
        # Control panel
        control_frame = tk.Frame(frame, bg='#2d2d2d', height=60)
        control_frame.pack(fill='x', padx=5, pady=5)
        control_frame.pack_propagate(False)
        
        tk.Label(
            control_frame,
            text="Directory:",
            font=('Arial', 10),
            fg='white',
            bg='#2d2d2d'
        ).pack(side='left', padx=5)
        
        self.scan_dir_var = tk.StringVar(value=str(Path.home()))
        
        tk.Entry(
            control_frame,
            textvariable=self.scan_dir_var,
            font=('Arial', 10),
            width=50
        ).pack(side='left', padx=5)
        
        tk.Button(
            control_frame,
            text="📂 Browse",
            command=self.browse_scan_directory,
            bg='#0066cc',
            fg='white',
            font=('Arial', 9, 'bold'),
            padx=10,
            pady=5
        ).pack(side='left', padx=5)
        
        tk.Button(
            control_frame,
            text="🔍 Scan",
            command=self.start_directory_scan,
            bg='#00aa00',
            fg='white',
            font=('Arial', 9, 'bold'),
            padx=15,
            pady=5
        ).pack(side='left', padx=5)
        
        self.scan_status_label = tk.Label(
            control_frame,
            text="Ready to scan",
            font=('Arial', 9),
            fg='#00ff00',
            bg='#2d2d2d'
        )
        self.scan_status_label.pack(side='left', padx=20)
        
        # Stats frame
        stats_frame = tk.Frame(frame, bg='#2d2d2d')
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        self.scan_files_label = tk.Label(
            stats_frame, text="Files Scanned: 0",
            font=('Arial', 10), fg='white', bg='#2d2d2d'
        )
        self.scan_files_label.pack(side='left', padx=20)
        
        self.scan_critical_label = tk.Label(
            stats_frame, text="Critical: 0",
            font=('Arial', 10), fg='#ff0000', bg='#2d2d2d'
        )
        self.scan_critical_label.pack(side='left', padx=20)
        
        self.scan_high_label = tk.Label(
            stats_frame, text="High: 0",
            font=('Arial', 10), fg='#ff6600', bg='#2d2d2d'
        )
        self.scan_high_label.pack(side='left', padx=20)
        
        # Filter
        filter_frame = tk.Frame(frame, bg='#2d2d2d')
        filter_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(
            filter_frame,
            text="Show:",
            font=('Arial', 9),
            fg='white',
            bg='#2d2d2d'
        ).pack(side='left', padx=5)
        
        self.scan_filter_var = tk.StringVar(value='all')
        
        for text, value in [('All', 'all'), ('High Risk', 'high'), ('Critical', 'critical')]:
            tk.Radiobutton(
                filter_frame,
                text=text,
                variable=self.scan_filter_var,
                value=value,
                command=self.update_scan_display,
                bg='#2d2d2d',
                fg='white',
                selectcolor='#0066cc',
                font=('Arial', 9)
            ).pack(side='left', padx=10)
        
        # Treeview for files
        tree_frame = tk.Frame(frame)
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        vsb = tk.Scrollbar(tree_frame, orient='vertical')
        hsb = tk.Scrollbar(tree_frame, orient='horizontal')
        
        columns = ('Filename', 'Path', 'Size', 'Ext', 'Entropy', 'Risk', 'Level', 'Factors', 'Modified')
        self.scan_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show='headings',
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )
        
        vsb.config(command=self.scan_tree.yview)
        hsb.config(command=self.scan_tree.xview)
        
        # Configure columns
        self.scan_tree.heading('Filename', text='Filename')
        self.scan_tree.heading('Path', text='Path')
        self.scan_tree.heading('Size', text='Size (MB)')
        self.scan_tree.heading('Ext', text='Type')
        self.scan_tree.heading('Entropy', text='Entropy')
        self.scan_tree.heading('Risk', text='Risk Score')
        self.scan_tree.heading('Level', text='Risk Level')
        self.scan_tree.heading('Factors', text='Risk Factors')
        self.scan_tree.heading('Modified', text='Modified')
        
        self.scan_tree.column('Filename', width=200)
        self.scan_tree.column('Path', width=300)
        self.scan_tree.column('Size', width=80, anchor='center')
        self.scan_tree.column('Ext', width=60, anchor='center')
        self.scan_tree.column('Entropy', width=70, anchor='center')
        self.scan_tree.column('Risk', width=80, anchor='center')
        self.scan_tree.column('Level', width=80, anchor='center')
        self.scan_tree.column('Factors', width=250)
        self.scan_tree.column('Modified', width=120, anchor='center')
        
        # Configure tags
        self.scan_tree.tag_configure('critical', background='#ffcccc')
        self.scan_tree.tag_configure('high', background='#ffe0cc')
        self.scan_tree.tag_configure('medium', background='#fff5cc')
        self.scan_tree.tag_configure('low', background='#f0f0f0')
        self.scan_tree.tag_configure('safe', background='#ccffcc')
        
        # Pack
        self.scan_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
    def create_metrics_tab(self):
        """Create resource metrics tab with live updating graphs"""
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text='📈 Resource Metrics')
        
        # Header with controls
        header_frame = tk.Frame(frame, bg='#2d2d2d', height=60)
        header_frame.pack(fill='x', padx=5, pady=5)
        header_frame.pack_propagate(False)
        
        tk.Label(
            header_frame,
            text="📊 LIVE RESOURCE METRICS",
            font=('Arial', 14, 'bold'),
            fg='#00ff00',
            bg='#2d2d2d'
        ).pack(side='left', padx=20)
        
        self.metrics_duration_label = tk.Label(
            header_frame,
            text="Duration: 0s",
            font=('Arial', 10),
            fg='#ffffff',
            bg='#2d2d2d'
        )
        self.metrics_duration_label.pack(side='left', padx=20)
        
        tk.Button(
            header_frame,
            text="🔄 Clear History",
            command=self.clear_metrics_history,
            bg='#ff6600',
            fg='white',
            font=('Arial', 9, 'bold'),
            padx=15,
            pady=5
        ).pack(side='right', padx=10)
        
        self.metrics_auto_update = tk.BooleanVar(value=True)
        tk.Checkbutton(
            header_frame,
            text="Auto-Update Graphs",
            variable=self.metrics_auto_update,
            bg='#2d2d2d',
            fg='white',
            selectcolor='#0066cc',
            font=('Arial', 9, 'bold')
        ).pack(side='right', padx=10)
        
        # Create matplotlib figure with 4 subplots
        self.metrics_fig = Figure(figsize=(14, 10), facecolor='#1e1e1e')
        
        # Create 2x2 grid of subplots
        self.ax_cpu = self.metrics_fig.add_subplot(2, 2, 1)
        self.ax_mem = self.metrics_fig.add_subplot(2, 2, 2)
        self.ax_net = self.metrics_fig.add_subplot(2, 2, 3)
        self.ax_disk = self.metrics_fig.add_subplot(2, 2, 4)
        
        # Metrics history already initialized in __init__, just reset the start time
        self.metrics_start_time = time.time()
        
        # Style all subplots
        for ax, title in [(self.ax_cpu, 'CPU Usage (%)'),
                          (self.ax_mem, 'Memory Usage (%)'),
                          (self.ax_net, 'Network Activity (KB/s)'),
                          (self.ax_disk, 'Disk I/O (MB/s)')]:
            ax.set_facecolor('#2d2d2d')
            ax.set_title(title, color='white', fontweight='bold', fontsize=12)
            ax.tick_params(colors='white', labelsize=9)
            ax.spines['bottom'].set_color('white')
            ax.spines['left'].set_color('white')
            ax.spines['top'].set_color('#2d2d2d')
            ax.spines['right'].set_color('#2d2d2d')
            ax.grid(True, alpha=0.2, color='white')
        
        self.metrics_fig.tight_layout(pad=3.0)
        
        self.metrics_canvas = FigureCanvasTkAgg(self.metrics_fig, frame)
        self.metrics_canvas.get_tk_widget().pack(fill='both', expand=True, padx=5, pady=5)
        
        # Start live metrics graphing
        self.update_metrics_graphs()
    
    def create_energy_tab(self):
        """Create energy/green computing analysis tab with real-time monitoring"""
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text='🌱 Energy/Green')
        
        # Header
        header_frame = tk.Frame(frame, bg='#1e4d2b', height=80)
        header_frame.pack(fill='x', padx=5, pady=5)
        header_frame.pack_propagate(False)
        
        tk.Label(
            header_frame,
            text="🌱 GREEN COMPUTING ANALYSIS - LIVE MONITORING",
            font=('Arial', 16, 'bold'),
            fg='#00ff00',
            bg='#1e4d2b'
        ).pack(pady=5)
        
        tk.Label(
            header_frame,
            text=f"Device: {DEVICE_MODEL} | System: {SYSTEM_NAME} | Baseline: {IDLE_W_BASELINE:.1f}W",
            font=('Arial', 10),
            fg='#ffffff',
            bg='#1e4d2b'
        ).pack()
        
        # Top section - Real-time energy gauge
        gauge_frame = tk.Frame(frame, bg='#2d2d2d', height=150)
        gauge_frame.pack(fill='x', padx=10, pady=10)
        gauge_frame.pack_propagate(False)
        
        tk.Label(
            gauge_frame,
            text="⚡ CURRENT POWER CONSUMPTION",
            font=('Arial', 14, 'bold'),
            fg='#00ff00',
            bg='#2d2d2d'
        ).pack(pady=5)
        
        # Real-time power display
        power_display_frame = tk.Frame(gauge_frame, bg='#1e1e1e')
        power_display_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Current power
        left_gauge = tk.Frame(power_display_frame, bg='#1e1e1e')
        left_gauge.pack(side='left', fill='both', expand=True)
        
        tk.Label(
            left_gauge,
            text="CURRENT POWER",
            font=('Arial', 10),
            fg='#888888',
            bg='#1e1e1e'
        ).pack(pady=5)
        
        self.current_power_label = tk.Label(
            left_gauge,
            text="0.0 W",
            font=('Arial', 32, 'bold'),
            fg='#ff6600',
            bg='#1e1e1e'
        )
        self.current_power_label.pack(pady=10)
        
        self.power_status_label = tk.Label(
            left_gauge,
            text="● Idle",
            font=('Arial', 12),
            fg='#00ff00',
            bg='#1e1e1e'
        )
        self.power_status_label.pack()
        
        # Separator
        tk.Frame(power_display_frame, bg='#888888', width=2).pack(side='left', fill='y', padx=20)
        
        # Theoretical power (if malware removed)
        right_gauge = tk.Frame(power_display_frame, bg='#1e1e1e')
        right_gauge.pack(side='right', fill='both', expand=True)
        
        tk.Label(
            right_gauge,
            text="THEORETICAL (Clean System)",
            font=('Arial', 10),
            fg='#888888',
            bg='#1e1e1e'
        ).pack(pady=5)
        
        self.theoretical_power_label = tk.Label(
            right_gauge,
            text="0.0 W",
            font=('Arial', 32, 'bold'),
            fg='#00ff00',
            bg='#1e1e1e'
        )
        self.theoretical_power_label.pack(pady=10)
        
        self.savings_label = tk.Label(
            right_gauge,
            text="Savings: 0.0 W",
            font=('Arial', 12),
            fg='#27ae60',
            bg='#1e1e1e'
        )
        self.savings_label.pack()
        
        # Middle section - Split view
        content_frame = tk.Frame(frame, bg='#2d2d2d')
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left: Current metrics
        left_frame = tk.Frame(content_frame, bg='#2d2d2d')
        left_frame.pack(side='left', fill='both', expand=True, padx=5)
        
        tk.Label(
            left_frame,
            text="📊 CURRENT ENERGY METRICS",
            font=('Arial', 12, 'bold'),
            fg='#ff6600',
            bg='#2d2d2d'
        ).pack(pady=10)
        
        # Energy metric cards
        self.energy_metric_labels = {}
        
        energy_metrics = [
            ('total_energy', 'Total Energy', 'J', '#e74c3c'),
            ('avg_power', 'Average Power', 'W', '#f39c12'),
            ('peak_power', 'Peak Power', 'W', '#e67e22'),
            ('co2_emissions', 'CO2 Emissions', 'g', '#7f8c8d'),
        ]
        
        for key, label, unit, color in energy_metrics:
            card = tk.Frame(left_frame, bg='#1e1e1e', relief='raised', bd=2)
            card.pack(fill='x', pady=5, padx=10)
            
            tk.Label(
                card,
                text=label,
                font=('Arial', 10),
                fg=color,
                bg='#1e1e1e'
            ).pack(side='left', padx=10, pady=10)
            
            value_label = tk.Label(
                card,
                text=f"0.0 {unit}",
                font=('Arial', 14, 'bold'),
                fg='#ffffff',
                bg='#1e1e1e'
            )
            value_label.pack(side='right', padx=10, pady=10)
            
            self.energy_metric_labels[key] = value_label
        
        # Right: Theoretical clean system metrics
        right_frame = tk.Frame(content_frame, bg='#2d2d2d')
        right_frame.pack(side='right', fill='both', expand=True, padx=5)
        
        tk.Label(
            right_frame,
            text="🌟 THEORETICAL CLEAN SYSTEM",
            font=('Arial', 12, 'bold'),
            fg='#00ff00',
            bg='#2d2d2d'
        ).pack(pady=10)
        
        # Theoretical metrics
        self.theoretical_metric_labels = {}
        
        theoretical_metrics = [
            ('total_energy', 'Total Energy', 'J', '#27ae60'),
            ('avg_power', 'Average Power', 'W', '#2ecc71'),
            ('savings', 'Energy Savings', 'J', '#16a085'),
            ('co2_saved', 'CO2 Saved', 'g', '#1abc9c'),
        ]
        
        for key, label, unit, color in theoretical_metrics:
            card = tk.Frame(right_frame, bg='#1e1e1e', relief='raised', bd=2)
            card.pack(fill='x', pady=5, padx=10)
            
            tk.Label(
                card,
                text=label,
                font=('Arial', 10),
                fg=color,
                bg='#1e1e1e'
            ).pack(side='left', padx=10, pady=10)
            
            value_label = tk.Label(
                card,
                text=f"0.0 {unit}",
                font=('Arial', 14, 'bold'),
                fg='#ffffff',
                bg='#1e1e1e'
            )
            value_label.pack(side='right', padx=10, pady=10)
            
            self.theoretical_metric_labels[key] = value_label
        
        # Bottom section - Impact analysis
        impact_frame = tk.Frame(frame, bg='#2d2d2d')
        impact_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        tk.Label(
            impact_frame,
            text="💡 MALWARE IMPACT & OPTIMIZATION POTENTIAL",
            font=('Arial', 12, 'bold'),
            fg='#00ff00',
            bg='#2d2d2d'
        ).pack(pady=10)
        
        self.energy_insights_text = scrolledtext.ScrolledText(
            impact_frame,
            font=('Consolas', 10),
            bg='#1e1e1e',
            fg='#00ff00',
            wrap='word',
            height=12
        )
        self.energy_insights_text.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Start live energy updates (slower rate to prevent lag)
        self.energy_update_job = None
        self.energy_data_cache = {
            'current_power': 0,
            'theoretical_power': 0,
            'savings': 0,
            'malicious_procs': 0,
            'malicious_files': 0
        }
        self.update_live_energy_display()
    
    def update_live_energy_display(self):
        """Update live energy display with current and theoretical clean system values (optimized)"""
        # Run calculation in background thread to prevent GUI lag
        def calculate_energy():
            try:
                # Get current CPU usage (non-blocking)
                cpu = psutil.cpu_percent(interval=0)  # Changed from 0.1 to 0 for speed
                
                # Calculate current power consumption
                dynamic_watts = (cpu / 100.0) * CPU_TDP_WATTS
                current_power = IDLE_W_BASELINE + dynamic_watts
                
                # Get malicious process overhead (limit to top 20 for performance)
                malicious_overhead_watts = 0
                malicious_process_count = 0
                
                # Only check if we're on the Process Monitor tab to save resources
                current_tab = self.notebook.tab(self.notebook.select(), "text")
                check_processes = "Process Monitor" in current_tab or "Energy" in current_tab
                
                if check_processes and hasattr(self, 'monitor'):
                    try:
                        # Use cached process data if available and recent
                        if hasattr(self.monitor, 'process_cache'):
                            processes = list(self.monitor.process_cache.values())[:20]  # Limit to 20
                        else:
                            processes = []
                        
                        # Calculate overhead from high-risk processes
                        for proc in processes:
                            if proc.get('risk_level') in ['CRITICAL', 'HIGH']:
                                proc_cpu = proc.get('cpu', 0)
                                proc_power = (proc_cpu / 100.0) * CPU_TDP_WATTS
                                malicious_overhead_watts += proc_power
                                malicious_process_count += 1
                    except:
                        pass
                
                # Get malicious file overhead from scanner (use cache)
                malicious_file_overhead = 0
                malicious_file_count = 0
                
                if hasattr(self, 'scanner') and hasattr(self.scanner, 'scan_results'):
                    try:
                        # Only count up to 10 most critical files for performance
                        critical_files = [f for f in self.scanner.scan_results 
                                        if f['risk_level'] in ['CRITICAL', 'HIGH']][:10]
                        malicious_file_count = len(critical_files)
                        malicious_file_overhead = malicious_file_count * 3.0
                    except:
                        pass
                
                # Calculate theoretical clean system power
                theoretical_power = current_power - malicious_overhead_watts - (malicious_file_overhead * 0.1)
                theoretical_power = max(IDLE_W_BASELINE, theoretical_power)
                
                # Calculate savings
                power_savings = max(0, current_power - theoretical_power)
                
                # Update cache
                self.energy_data_cache = {
                    'current_power': current_power,
                    'theoretical_power': theoretical_power,
                    'savings': power_savings,
                    'malicious_procs': malicious_process_count,
                    'malicious_files': malicious_file_count
                }
                
                # Schedule GUI update in main thread
                self.root.after(0, self._update_energy_gui)
                
            except Exception as e:
                print(f"Error calculating energy: {e}")
        
        # Run calculation in background thread
        threading.Thread(target=calculate_energy, daemon=True).start()
        
        # Schedule next update (every 2 seconds instead of 1 for better performance)
        self.energy_update_job = self.root.after(2000, self.update_live_energy_display)
    
    def _update_energy_gui(self):
        """Update GUI elements with cached energy data (runs in main thread)"""
        try:
            current_power = self.energy_data_cache['current_power']
            theoretical_power = self.energy_data_cache['theoretical_power']
            power_savings = self.energy_data_cache['savings']
            malicious_process_count = self.energy_data_cache['malicious_procs']
            malicious_file_count = self.energy_data_cache['malicious_files']
            
            # Update current power display
            self.current_power_label.config(text=f"{current_power:.1f} W")
            
            # Color code based on power level
            if current_power > IDLE_W_BASELINE * 3:
                self.current_power_label.config(fg='#ff0000')
                self.power_status_label.config(text="● Very High Load", fg='#ff0000')
            elif current_power > IDLE_W_BASELINE * 2:
                self.current_power_label.config(fg='#ff6600')
                self.power_status_label.config(text="● High Load", fg='#ff6600')
            elif current_power > IDLE_W_BASELINE * 1.5:
                self.current_power_label.config(fg='#ffaa00')
                self.power_status_label.config(text="● Moderate Load", fg='#ffaa00')
            else:
                self.current_power_label.config(fg='#00ff00')
                self.power_status_label.config(text="● Idle/Low", fg='#00ff00')
            
            # Update theoretical power display
            self.theoretical_power_label.config(text=f"{theoretical_power:.1f} W")
            
            if power_savings > 0.5:  # Only show if meaningful savings
                percentage = (power_savings/current_power)*100 if current_power > 0 else 0
                self.savings_label.config(
                    text=f"Savings: {power_savings:.1f} W ({percentage:.1f}%)",
                    fg='#27ae60'
                )
            else:
                self.savings_label.config(text="System is clean!", fg='#00ff00')
            
            # Update current energy metrics (only if monitoring is active)
            if hasattr(self.monitor, 'energy_analyzer') and self.monitor.energy_analyzer.energy_history:
                energy_metrics = self.monitor.energy_analyzer.calculate_metrics()
                
                self.energy_metric_labels['total_energy'].config(
                    text=f"{energy_metrics.get('total_energy_j', 0):.1f} J"
                )
                self.energy_metric_labels['avg_power'].config(
                    text=f"{energy_metrics.get('avg_power_w', 0):.1f} W"
                )
                self.energy_metric_labels['peak_power'].config(
                    text=f"{energy_metrics.get('peak_power_w', 0):.1f} W"
                )
                self.energy_metric_labels['co2_emissions'].config(
                    text=f"{energy_metrics.get('co2_grams', 0):.4f} g"
                )
                
                # Calculate theoretical clean system metrics
                duration = len(self.monitor.energy_analyzer.energy_history)
                if duration > 0:
                    theoretical_energy = theoretical_power * duration
                    current_energy = energy_metrics.get('total_energy_j', 0)
                    energy_savings = max(0, current_energy - theoretical_energy)
                    
                    # Theoretical CO2 (0.82g per Wh)
                    theoretical_co2 = (theoretical_energy / 3600) * 0.82
                    co2_savings = max(0, energy_metrics.get('co2_grams', 0) - theoretical_co2)
                    
                    self.theoretical_metric_labels['total_energy'].config(
                        text=f"{theoretical_energy:.1f} J"
                    )
                    self.theoretical_metric_labels['avg_power'].config(
                        text=f"{theoretical_power:.1f} W"
                    )
                    self.theoretical_metric_labels['savings'].config(
                        text=f"{energy_savings:.1f} J"
                    )
                    self.theoretical_metric_labels['co2_saved'].config(
                        text=f"{co2_savings:.4f} g"
                    )
            
            # Update insights text (less frequently - only if savings changed significantly)
            if not hasattr(self, '_last_savings') or abs(self._last_savings - power_savings) > 5.0:
                self._update_energy_insights(
                    current_power, 
                    theoretical_power, 
                    power_savings,
                    malicious_process_count,
                    malicious_file_count
                )
                self._last_savings = power_savings
            
        except Exception as e:
            print(f"Error updating energy GUI: {e}")
    
    def _update_energy_insights(self, current_power, theoretical_power, savings, 
                                malicious_procs, malicious_files):
        """Update the energy insights text with real-time analysis (optimized)"""
        if not hasattr(self, 'energy_insights_text'):
            return
        
        # Build text efficiently
        lines = []
        lines.append("💡 REAL-TIME ENERGY IMPACT ANALYSIS")
        lines.append("=" * 70)
        lines.append("")
        
        # Current status
        lines.append(f"⚡ CURRENT POWER: {current_power:.1f} W")
        lines.append(f"🌟 CLEAN SYSTEM:  {theoretical_power:.1f} W")
        lines.append(f"💰 SAVINGS:       {savings:.1f} W")
        lines.append("")
        
        # Threat summary
        total_threats = malicious_procs + malicious_files
        lines.append("🚨 DETECTED THREATS:")
        lines.append("-" * 70)
        lines.append(f"High-risk Processes: {malicious_procs}")
        lines.append(f"Malicious Files: {malicious_files}")
        
        if total_threats > 0:
            lines.append(f"\n⚠️  {total_threats} THREATS CONSUMING EXTRA ENERGY!")
        else:
            lines.append("\n✅ NO ACTIVE THREATS DETECTED")
        lines.append("")
        
        # Savings calculations (only if significant)
        if savings > 1.0:
            lines.append("💡 IF THREATS WERE REMOVED:")
            lines.append("-" * 70)
            
            # Quick calculations
            hourly_wh = savings
            daily_wh = savings * 24
            monthly_kwh = (savings * 24 * 30) / 1000
            
            lines.append(f"Hourly:  {hourly_wh:.1f} Wh")
            lines.append(f"Daily:   {daily_wh:.1f} Wh")
            lines.append(f"Monthly: {monthly_kwh:.2f} kWh")
            lines.append("")
            
            # Cost & CO2 (0.82g CO2 per Wh = 820g per kWh = 0.82kg per kWh)
            monthly_cost = monthly_kwh * 0.12
            yearly_cost = monthly_cost * 12
            yearly_co2_kg = (monthly_kwh * 12) * 0.82  # 0.82kg CO2 per kWh
            
            lines.append(f"Yearly Cost: ${yearly_cost:.2f}")
            lines.append(f"Yearly CO2:  {yearly_co2_kg:.1f} kg")
            lines.append("")
            
            # Simple equivalents
            trees = yearly_co2_kg / 21
            lines.append(f"🌳 Trees needed: {trees:.1f}")
            lines.append("")
        
        # Recommendations
        lines.append("🎯 ACTIONS:")
        lines.append("-" * 70)
        
        if malicious_procs > 0:
            lines.append(f"1. TERMINATE {malicious_procs} high-risk processes")
        if malicious_files > 0:
            lines.append(f"2. REMOVE {malicious_files} malicious files")
        if total_threats > 0:
            lines.append("3. RUN antivirus scan")
        else:
            lines.append("✅ System is clean - continue monitoring")
        
        lines.append("")
        lines.append("🌱 Clean systems = Lower energy = Better planet!")
        
        # Update text widget efficiently
        text = "\n".join(lines)
        self.energy_insights_text.delete('1.0', 'end')
        self.energy_insights_text.insert('1.0', text)
        
    def create_scores_tab(self):
        """Create trust scores tab"""
        frame = tk.Frame(self.notebook)
        self.notebook.add(frame, text='🏆 Trust Scores')
        
        self.trust_summary_label = tk.Label(frame, text="", font=('Arial', 14, 'bold'), fg='#2c3e50')
        self.trust_summary_label.pack(pady=10)
        
        self.trust_fig = Figure(figsize=(10, 6))
        self.trust_canvas = FigureCanvasTkAgg(self.trust_fig, frame)
        self.trust_canvas.get_tk_widget().pack(fill='both', expand=True)
        
    def load_file(self):
        """Load a binary file"""
        filename = filedialog.askopenfilename(
            title="Select Binary File",
            filetypes=[("All Files", "*.*"), ("Executables", "*.exe;*.dll;*.bin")]
        )
        
        if filename:
            self.current_file = filename
            self.update_status(f"Loaded: {Path(filename).name}", "blue")
            
    def perform_analysis(self):
        """Perform comprehensive analysis"""
        if not self.current_file:
            messagebox.showwarning("No File", "Please load a binary file first!")
            return
        
        self.update_status("🔬 Analyzing...", "orange")
        self.root.update()
        
        # Start resource monitoring
        self.monitor.start_monitoring()
        
        # Perform analysis in separate thread
        def analyze():
            try:
                self.analysis_results = self.engine.analyze_binary(self.current_file)
                self.root.after(0, self.display_results)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Analysis failed: {e}"))
                self.update_status("Analysis failed", "red")
        
        threading.Thread(target=analyze, daemon=True).start()
        
        # Stop monitoring after 5 seconds
        def stop_monitor():
            time.sleep(5)
            self.monitor.stop_monitoring()
            self.root.after(0, lambda: self.update_status("✅ Analysis complete", "green"))
            
        threading.Thread(target=stop_monitor, daemon=True).start()
        
    def display_results(self):
        """Display analysis results"""
        try:
            print(f"DEBUG: Displaying results. analysis_results is {'available' if self.analysis_results else 'None'}")
            
            # Overview
            self.display_overview()
            
            # Disassembly
            self.display_disassembly()
            
            # Control Flow
            self.display_control_flow()
            
            # Detailed Analysis (includes trust scores)
            self.display_detailed_analysis()
            print("DEBUG: Detailed analysis displayed")
            
            # Note: Metrics graphs update automatically via update_metrics_graphs()
            # No need to plot here
            
            # Trust Scores (separate tab)
            resource_summary = self.monitor.calculate_summary()
            energy_metrics = resource_summary.get('energy_metrics', {})
            trust_scores = TrustScoreCalculator.calculate_trust_score(
                self.analysis_results,
                resource_summary,
                energy_metrics
            )
            self._plot_trust_scores(trust_scores)
            print(f"DEBUG: Trust scores plotted. Overall: {trust_scores.get('overall_score', 'N/A')}")
            
            # Switch to Detailed Analysis tab to show results
            for i in range(self.notebook.index('end')):
                if 'Detailed Analysis' in self.notebook.tab(i, 'text'):
                    self.notebook.select(i)
                    print(f"DEBUG: Switched to Detailed Analysis tab (index {i})")
                    break
            
        except Exception as e:
            print(f"ERROR in display_results: {e}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Display Error", f"Error displaying results: {e}")
        
    def display_overview(self):
        """Display overview"""
        self.overview_text.delete('1.0', 'end')
        
        text = "=" * 80 + "\n"
        text += "ENHANCED SOFTWARE TRANSPARENCY ANALYZER - ANALYSIS REPORT\n"
        text += "=" * 80 + "\n\n"
        
        file_info = self.analysis_results['file_info']
        text += f"FILE INFORMATION:\n"
        text += f"  Filename: {file_info['filename']}\n"
        text += f"  Size: {file_info['size_bytes']:,} bytes ({file_info['size_mb']} MB)\n"
        text += f"  MD5: {file_info['md5']}\n"
        text += f"  SHA256: {file_info['sha256']}\n\n"
        
        # Binary Format
        binary_fmt = self.analysis_results.get('binary_format')
        if binary_fmt:
            text += f"BINARY FORMAT:\n"
            text += f"  Format: {binary_fmt['format']}\n"
            text += f"  Architecture: {binary_fmt['architecture']}\n"
            if 'sections' in binary_fmt:
                text += f"  Sections: {binary_fmt['sections']}\n"
            text += "\n"
        
        # Disassembly Summary
        disasm = self.analysis_results.get('disassembly', {})
        text += f"DISASSEMBLY:\n"
        text += f"  Instructions Analyzed: {disasm.get('total_instructions', 0)}\n\n"
        
        # Control Flow Summary
        cf = self.analysis_results.get('control_flow', {})
        metrics = cf.get('metrics', {})
        text += f"CONTROL FLOW ANALYSIS:\n"
        text += f"  Basic Blocks: {cf.get('basic_blocks_count', 0)}\n"
        text += f"  Functions Detected: {cf.get('functions_count', 0)}\n"
        text += f"  Avg Cyclomatic Complexity: {metrics.get('avg_cyclomatic_complexity', 0)}\n\n"
        
        # Crypto Detection
        crypto = self.analysis_results.get('crypto_detection', {})
        text += f"CRYPTOGRAPHIC ANALYSIS:\n"
        text += f"  Algorithms Detected: {', '.join(crypto.get('constants', [])) or 'None'}\n"
        text += f"  High-Entropy Blocks: {crypto.get('high_entropy_blocks', 0)}\n\n"
        
        # Code Patterns
        patterns = self.analysis_results.get('code_patterns', {})
        text += f"CODE PATTERNS:\n"
        for ptype, count in patterns.items():
            if ptype != 'error':
                text += f"  {ptype}: {count}\n"
        
        self.overview_text.insert('1.0', text)
        
    def display_disassembly(self):
        """Display disassembly"""
        self.disasm_text.delete('1.0', 'end')
        
        disasm = self.analysis_results.get('disassembly', {})
        instructions = disasm.get('sample_instructions', [])
        
        if instructions:
            text = "Address      Opcode           Mnemonic  Operands\n"
            text += "-" * 80 + "\n"
            
            for instr in instructions:
                addr = instr['address']
                opcode = instr['opcode'].ljust(16)
                mnemonic = instr['mnemonic'].ljust(8)
                operands = instr['operands']
                
                text += f"{addr}  {opcode}  {mnemonic}  {operands}\n"
            
            self.disasm_text.insert('1.0', text)
        else:
            self.disasm_text.insert('1.0', "No disassembly data available")
            
    def display_control_flow(self):
        """Display control flow analysis"""
        self.cfg_text.delete('1.0', 'end')
        
        cf = self.analysis_results.get('control_flow', {})
        
        text = "CONTROL FLOW GRAPH ANALYSIS\n"
        text += "=" * 80 + "\n\n"
        
        text += f"Total Basic Blocks: {cf.get('basic_blocks_count', 0)}\n"
        text += f"Total Functions: {cf.get('functions_count', 0)}\n\n"
        
        # Display functions
        functions = cf.get('functions', [])
        if functions:
            text += "DETECTED FUNCTIONS:\n"
            text += "-" * 80 + "\n"
            for func in functions:
                text += f"\n{func['name']} @ {func['start']}\n"
                text += f"  End Address: {func['end']}\n"
                text += f"  Basic Blocks: {func['blocks']}\n"
                text += f"  Complexity: {func['complexity']}\n"
        
        # Display basic blocks
        blocks = cf.get('basic_blocks', [])
        if blocks:
            text += "\n\nBASIC BLOCKS (Sample):\n"
            text += "-" * 80 + "\n"
            for bb in blocks[:10]:
                text += f"\nBlock {bb['start']} - {bb['end']}\n"
                text += f"  Size: {bb['size']} instructions\n"
                text += f"  Successors: {bb['successors']}\n"
                if bb['is_entry']:
                    text += "  [ENTRY BLOCK]\n"
                if bb['is_exit']:
                    text += "  [EXIT BLOCK]\n"
        
        self.cfg_text.insert('1.0', text)
        
    def display_detailed_analysis(self):
        """Display detailed analysis with trust score breakdown"""
        self.analysis_text.delete('1.0', 'end')
        
        # Safety check - ensure analysis_results exists
        if not self.analysis_results:
            self.analysis_text.insert('1.0', "No analysis results available.\nPlease load a file and click 'Analyze' first.")
            return
        
        # Calculate trust scores with energy metrics
        resource_summary = self.monitor.calculate_summary()
        energy_metrics = resource_summary.get('energy_metrics', {})
        trust_scores = TrustScoreCalculator.calculate_trust_score(
            self.analysis_results,
            resource_summary,
            energy_metrics
        )
        
        # Update trust score display in the analysis tab
        overall = trust_scores['overall_score']
        rating = trust_scores['rating']
        
        # Set overall score with color
        self.overall_score_label.config(text=f"Overall Score: {overall} / 100")
        if overall >= 85:
            self.overall_score_label.config(fg='#00ff00')  # Green - Excellent
        elif overall >= 70:
            self.overall_score_label.config(fg='#00ffaa')  # Light green - Good
        elif overall >= 55:
            self.overall_score_label.config(fg='#ffaa00')  # Orange - Fair
        else:
            self.overall_score_label.config(fg='#ff0000')  # Red - Poor
        
        self.rating_label.config(text=f"Rating: {rating}")
        
        # Update individual scores
        self.score_labels['transparency'].config(text=f"{trust_scores['transparency_score']} / 100")
        self.score_labels['security'].config(text=f"{trust_scores['security_score']} / 100")
        self.score_labels['efficiency'].config(text=f"{trust_scores['efficiency_score']} / 100")
        self.score_labels['sustainability'].config(text=f"{trust_scores['sustainability_score']} / 100")
        self.score_labels['re_quality'].config(text=f"{trust_scores['re_quality_score']} / 100")
        self.score_labels['energy'].config(text=f"{trust_scores['energy_score']} / 100")
        
        # Create or update CO2 emissions banner if not exists
        if not hasattr(self, 'co2_banner_created'):
            # Create CO2 emissions banner between scores and detailed analysis
            co2_banner = tk.Frame(self.trust_breakdown_frame, bg='#1e4d2b', relief='raised', bd=3)
            co2_banner.pack(fill='x', pady=15, padx=10)
            
            tk.Label(
                co2_banner,
                text="🌍 CARBON EMISSIONS ANALYSIS",
                font=('Arial', 14, 'bold'),
                fg='#00ff00',
                bg='#1e4d2b'
            ).pack(pady=5)
            
            emissions_grid = tk.Frame(co2_banner, bg='#1e4d2b')
            emissions_grid.pack(pady=10)
            
            # Current emissions
            left_co2 = tk.Frame(emissions_grid, bg='#1e1e1e', relief='raised', bd=2)
            left_co2.pack(side='left', padx=10, pady=5)
            
            tk.Label(
                left_co2,
                text="Current CO2 Emissions",
                font=('Arial', 10),
                fg='#888888',
                bg='#1e1e1e'
            ).pack(pady=5, padx=15)
            
            self.co2_current_label = tk.Label(
                left_co2,
                text="0.0000 g",
                font=('Arial', 20, 'bold'),
                fg='#ff6600',
                bg='#1e1e1e'
            )
            self.co2_current_label.pack(pady=10, padx=15)
            
            # Conversion factor display
            center_co2 = tk.Frame(emissions_grid, bg='#1e1e1e', relief='raised', bd=2)
            center_co2.pack(side='left', padx=10, pady=5)
            
            tk.Label(
                center_co2,
                text="Conversion Factor",
                font=('Arial', 10),
                fg='#888888',
                bg='#1e1e1e'
            ).pack(pady=5, padx=15)
            
            tk.Label(
                center_co2,
                text="0.82 g/Wh",
                font=('Arial', 16, 'bold'),
                fg='#00aaff',
                bg='#1e1e1e'
            ).pack(pady=10, padx=15)
            
            tk.Label(
                center_co2,
                text="(820 g/kWh)",
                font=('Arial', 9),
                fg='#666666',
                bg='#1e1e1e'
            ).pack(pady=(0, 10), padx=15)
            
            # Energy consumed
            right_co2 = tk.Frame(emissions_grid, bg='#1e1e1e', relief='raised', bd=2)
            right_co2.pack(side='left', padx=10, pady=5)
            
            tk.Label(
                right_co2,
                text="Energy Consumed",
                font=('Arial', 10),
                fg='#888888',
                bg='#1e1e1e'
            ).pack(pady=5, padx=15)
            
            self.energy_wh_label = tk.Label(
                right_co2,
                text="0.0 Wh",
                font=('Arial', 20, 'bold'),
                fg='#ffaa00',
                bg='#1e1e1e'
            )
            self.energy_wh_label.pack(pady=10, padx=15)
            
            self.co2_banner_created = True
        
        # Update CO2 banner values
        energy_metrics = resource_summary.get('energy_metrics', {})
        if energy_metrics:
            co2_grams = energy_metrics.get('co2_grams', 0)
            total_energy_j = energy_metrics.get('total_energy_j', 0)
            energy_wh = total_energy_j / 3600  # Convert J to Wh
            
            self.co2_current_label.config(text=f"{co2_grams:.4f} g")
            self.energy_wh_label.config(text=f"{energy_wh:.2f} Wh")
            
            # Color code based on CO2 level
            if co2_grams > 1.0:
                self.co2_current_label.config(fg='#ff0000')  # Red - high
            elif co2_grams > 0.5:
                self.co2_current_label.config(fg='#ff6600')  # Orange - moderate
            elif co2_grams > 0.1:
                self.co2_current_label.config(fg='#ffaa00')  # Yellow - low
            else:
                self.co2_current_label.config(fg='#00ff00')  # Green - very low
        
        # Update energy metrics if available (existing code)
        if energy_metrics and hasattr(self, 'energy_metric_labels'):
            self.energy_metric_labels['total_energy'].config(text=f"{energy_metrics.get('total_energy_j', 0):.1f} J")
            self.energy_metric_labels['avg_power'].config(text=f"{energy_metrics.get('avg_power_w', 0):.1f} W")
            self.energy_metric_labels['peak_power'].config(text=f"{energy_metrics.get('peak_power_w', 0):.1f} W")
            self.energy_metric_labels['co2_emissions'].config(text=f"{energy_metrics.get('co2_grams', 0):.4f} g")
            # Note: energy_waste and efficiency are not in the new Energy tab design
            
            # Update green insights
            if hasattr(self, 'energy_insights_text'):
                self.energy_insights_text.delete('1.0', 'end')
                insights = self._generate_green_insights(energy_metrics, trust_scores)
                self.energy_insights_text.insert('1.0', insights)
        
        # Build detailed text explanation
        text = "=" * 80 + "\n"
        text += "TRUST SCORE CALCULATION BREAKDOWN\n"
        text += "=" * 80 + "\n\n"
        
        text += "🏆 OVERALL TRUST SCORE FORMULA:\n"
        text += "-" * 80 + "\n"
        text += "Overall Score = (Transparency × 25%) + (Security × 35%) + \n"
        text += "                (Efficiency × 20%) + (Sustainability × 15%) + \n"
        text += "                (RE Quality × 5%)\n\n"
        
        text += f"Overall Score = ({trust_scores['transparency_score']} × 0.25) + "
        text += f"({trust_scores['security_score']} × 0.35) + \n"
        text += f"                ({trust_scores['efficiency_score']} × 0.20) + "
        text += f"({trust_scores['sustainability_score']} × 0.15) + \n"
        text += f"                ({trust_scores['re_quality_score']} × 0.05)\n"
        text += f"Overall Score = {overall} / 100\n"
        text += f"Rating: {rating}\n\n"
        
        text += "=" * 80 + "\n"
        text += "INDIVIDUAL SCORE BREAKDOWNS\n"
        text += "=" * 80 + "\n\n"
        
        # 1. Transparency Score
        text += f"1️⃣ TRANSPARENCY SCORE: {trust_scores['transparency_score']} / 100\n"
        text += "-" * 80 + "\n"
        text += "Measures: Code obfuscation, encryption, packing\n"
        text += "Calculation: Base 100 - (Entropy/8.0 × 40)\n"
        
        entropy = self.analysis_results.get('entropy_analysis', {}).get('entropy', 0)
        text += f"\nEntropy: {entropy} / 8.0\n"
        text += f"Deduction: {round((entropy / 8.0) * 40, 2)} points\n"
        text += f"Final: 100 - {round((entropy / 8.0) * 40, 2)} = {trust_scores['transparency_score']}\n\n"
        
        if entropy > 7.5:
            text += "⚠️  Very High Entropy - Likely encrypted or packed\n"
        elif entropy > 6.5:
            text += "⚠️  High Entropy - Possible obfuscation\n"
        elif entropy > 4.5:
            text += "✓ Normal Entropy - Standard executable\n"
        else:
            text += "✓ Low Entropy - Clear code/data\n"
        text += "\n"
        
        # 2. Security Score
        text += f"2️⃣ SECURITY SCORE: {trust_scores['security_score']} / 100\n"
        text += "-" * 80 + "\n"
        text += "Measures: Suspicious patterns, risky imports, malicious indicators\n"
        text += "Calculation: Base 100 - Deductions\n\n"
        
        suspicious_count = self.analysis_results.get('strings_analysis', {}).get('suspicious_count', 0)
        risky_imports = len(self.analysis_results.get('imports_exports', {}).get('suspicious_imports', []))
        url_patterns = self.analysis_results.get('suspicious_patterns', {}).get('url_patterns', 0)
        
        text += f"Suspicious Strings: {suspicious_count} × 5 = -{suspicious_count * 5} points\n"
        text += f"Risky Imports: {risky_imports} × 10 = -{risky_imports * 10} points\n"
        text += f"URL Patterns: {url_patterns} × 2 = -{url_patterns * 2} points\n"
        
        total_deductions = (suspicious_count * 5) + (risky_imports * 10) + (url_patterns * 2)
        text += f"\nTotal Deductions: {total_deductions}\n"
        text += f"Final: max(0, 100 - {total_deductions}) = {trust_scores['security_score']}\n\n"
        
        if trust_scores['security_score'] < 50:
            text += "🚨 CRITICAL - High security risk detected!\n"
        elif trust_scores['security_score'] < 70:
            text += "⚠️  WARNING - Security concerns present\n"
        else:
            text += "✓ GOOD - No major security issues\n"
        text += "\n"
        
        # 3. Efficiency Score
        text += f"3️⃣ EFFICIENCY SCORE: {trust_scores['efficiency_score']} / 100\n"
        text += "-" * 80 + "\n"
        text += "Measures: CPU and memory resource usage\n"
        text += "Calculation: Base 100 - (CPU% × 0.5) - (Memory MB × 0.01)\n\n"
        
        resource_summary = self.monitor.calculate_summary()
        cpu_avg = resource_summary.get('cpu_avg', 0)
        memory_avg = resource_summary.get('memory_avg', 0)
        
        text += f"Average CPU: {cpu_avg}% × 0.5 = -{round(cpu_avg * 0.5, 2)} points\n"
        text += f"Average Memory: {memory_avg} MB × 0.01 = -{round(memory_avg * 0.01, 2)} points\n"
        text += f"\nFinal: max(0, 100 - {round(cpu_avg * 0.5, 2)} - {round(memory_avg * 0.01, 2)}) = {trust_scores['efficiency_score']}\n\n"
        
        if trust_scores['efficiency_score'] < 60:
            text += "⚠️  INEFFICIENT - High resource consumption\n"
        else:
            text += "✓ EFFICIENT - Acceptable resource usage\n"
        text += "\n"
        
        # 4. Sustainability Score
        text += f"4️⃣ SUSTAINABILITY SCORE: {trust_scores['sustainability_score']} / 100\n"
        text += "-" * 80 + "\n"
        text += "Measures: Network and disk I/O activity\n"
        text += "Calculation: Base 100 - (Network MB × 2) - (Disk MB × 0.5)\n\n"
        
        network_total = resource_summary.get('network_sent_total', 0) + resource_summary.get('network_recv_total', 0)
        disk_total = resource_summary.get('disk_read_total', 0) + resource_summary.get('disk_write_total', 0)
        
        text += f"Network Total: {network_total} MB × 2 = -{round(network_total * 2, 2)} points\n"
        text += f"Disk Total: {disk_total} MB × 0.5 = -{round(disk_total * 0.5, 2)} points\n"
        text += f"\nFinal: max(0, 100 - {round(network_total * 2, 2)} - {round(disk_total * 0.5, 2)}) = {trust_scores['sustainability_score']}\n\n"
        
        # 5. RE Quality Score
        text += f"5️⃣ REVERSE ENGINEERING QUALITY SCORE: {trust_scores['re_quality_score']} / 100\n"
        text += "-" * 80 + "\n"
        text += "Measures: Depth and quality of reverse engineering analysis\n"
        text += "Calculation: min(100, (Instructions/10) + (Functions × 5))\n\n"
        
        disasm_count = self.analysis_results.get('disassembly', {}).get('total_instructions', 0)
        functions_count = self.analysis_results.get('control_flow', {}).get('functions_count', 0)
        
        text += f"Instructions Disassembled: {disasm_count} / 10 = {round(disasm_count / 10, 2)} points\n"
        text += f"Functions Detected: {functions_count} × 5 = {functions_count * 5} points\n"
        text += f"\nFinal: min(100, {round(disasm_count / 10, 2)} + {functions_count * 5}) = {trust_scores['re_quality_score']}\n\n"
        
        # NEW: CO2 Emissions Breakdown
        text += "🌍 CARBON EMISSIONS ANALYSIS\n"
        text += "=" * 80 + "\n"
        text += "Environmental Impact Assessment\n\n"
        
        energy_metrics = resource_summary.get('energy_metrics', {})
        if energy_metrics:
            total_energy_j = energy_metrics.get('total_energy_j', 0)
            energy_wh = total_energy_j / 3600  # Convert Joules to Wh
            co2_grams = energy_metrics.get('co2_grams', 0)
            
            text += "CONVERSION FORMULA:\n"
            text += "-" * 80 + "\n"
            text += "Step 1: Convert Energy from Joules to Watt-hours\n"
            text += f"  Energy (Wh) = Energy (J) ÷ 3600\n"
            text += f"  Energy (Wh) = {total_energy_j:.2f} J ÷ 3600\n"
            text += f"  Energy (Wh) = {energy_wh:.4f} Wh\n\n"
            
            text += "Step 2: Calculate CO2 Emissions\n"
            text += "  CO2 (grams) = Energy (Wh) × 0.82 g/Wh\n"
            text += f"  CO2 (grams) = {energy_wh:.4f} Wh × 0.82 g/Wh\n"
            text += f"  CO2 (grams) = {co2_grams:.4f} g\n\n"
            
            text += "CONVERSION FACTOR EXPLAINED:\n"
            text += "-" * 80 + "\n"
            text += "• 1 Wh of power = 0.82 g CO2 emissions\n"
            text += "• 1 kWh (1000 Wh) = 820 g (0.82 kg) CO2 emissions\n"
            text += "• Based on average global electricity grid carbon intensity\n\n"
            
            # Environmental context
            text += "ENVIRONMENTAL CONTEXT:\n"
            text += "-" * 80 + "\n"
            
            if co2_grams > 0:
                # Tree absorption (1 tree absorbs ~21kg CO2/year = 57.5mg/day)
                tree_hours = (co2_grams / 1000) / (21 / (365 * 24))  # Hours of tree absorption
                text += f"Tree Absorption: {tree_hours:.2f} hours needed by 1 tree\n"
                
                # Car equivalent (average car: 404g CO2 per mile)
                car_meters = (co2_grams / 404) * 1609  # meters
                if car_meters < 1:
                    text += f"Car Equivalent: {car_meters * 100:.1f} cm driven\n"
                else:
                    text += f"Car Equivalent: {car_meters:.1f} meters driven\n"
                
                # Phone charges (1 phone charge ≈ 3Wh)
                phone_charges = energy_wh / 3
                text += f"Phone Charges: {phone_charges:.2f} smartphone charges\n\n"
            
            # Assessment
            text += "EMISSIONS ASSESSMENT:\n"
            text += "-" * 80 + "\n"
            
            if co2_grams < 0.01:
                text += "✅ EXCELLENT - Negligible carbon footprint (<0.01g)\n"
            elif co2_grams < 0.1:
                text += "✅ VERY GOOD - Very low emissions (0.01-0.1g)\n"
            elif co2_grams < 0.5:
                text += "🟡 GOOD - Low emissions (0.1-0.5g)\n"
            elif co2_grams < 1.0:
                text += "🟠 MODERATE - Moderate emissions (0.5-1.0g)\n"
            else:
                text += "🔴 HIGH - Significant emissions (>1.0g)\n"
                text += "    ⚠️  Consider energy optimization!\n"
            
            text += "\n"
        
        text += "\n" + "=" * 80 + "\n"
        text += "DETAILED ANALYSIS RESULTS\n"
        text += "=" * 80 + "\n\n"
        
        # Entropy
        entropy = self.analysis_results.get('entropy_analysis', {})
        text += f"ENTROPY ANALYSIS:\n"
        text += f"  Entropy: {entropy.get('entropy', 0)}/8.0\n"
        text += f"  Assessment: {entropy.get('assessment', 'N/A')}\n\n"
        
        # Strings
        strings = self.analysis_results.get('strings_analysis', {})
        text += f"STRING ANALYSIS:\n"
        text += f"  Total Strings: {strings.get('total_strings', 0)}\n"
        text += f"  Suspicious Strings: {strings.get('suspicious_count', 0)}\n"
        if strings.get('suspicious_strings'):
            text += "  Examples:\n"
            for s in strings['suspicious_strings'][:5]:
                text += f"    - {s[:60]}\n"
        text += "\n"
        
        # Imports
        imports = self.analysis_results.get('imports_exports', {})
        text += f"IMPORTS ANALYSIS:\n"
        text += f"  Risk Level: {imports.get('risk_level', 'N/A')}\n"
        if imports.get('suspicious_imports'):
            text += "  Suspicious Imports:\n"
            for imp in imports['suspicious_imports']:
                text += f"    - {imp}\n"
        text += "\n"
        
        # Suspicious Patterns
        patterns = self.analysis_results.get('suspicious_patterns', {})
        text += f"SUSPICIOUS PATTERNS:\n"
        text += f"  URLs: {patterns.get('url_patterns', 0)}\n"
        text += f"  IP Addresses: {patterns.get('ip_patterns', 0)}\n"
        text += f"  Registry Keys: {patterns.get('registry_keys', 0)}\n"
        text += f"  Encoded Data: {patterns.get('encoded_data', 0)}\n\n"
        
        # Crypto Detection
        crypto = self.analysis_results.get('crypto_detection', {})
        text += f"CRYPTOGRAPHIC ANALYSIS:\n"
        if crypto.get('constants'):
            text += f"  Algorithms Detected: {', '.join(crypto['constants'])}\n"
        else:
            text += f"  No crypto algorithms detected\n"
        text += f"  High-Entropy Blocks: {crypto.get('high_entropy_blocks', 0)}\n\n"
        
        # Resource Summary
        text += f"RESOURCE USAGE SUMMARY:\n"
        text += f"  CPU Avg: {resource_summary.get('cpu_avg', 0)}%\n"
        text += f"  CPU Max: {resource_summary.get('cpu_max', 0)}%\n"
        text += f"  Memory Avg: {resource_summary.get('memory_avg', 0)} MB\n"
        text += f"  Memory Max: {resource_summary.get('memory_max', 0)} MB\n"
        text += f"  Network Sent: {resource_summary.get('network_sent_total', 0)} MB\n"
        text += f"  Network Received: {resource_summary.get('network_recv_total', 0)} MB\n"
        text += f"  Duration: {resource_summary.get('duration_seconds', 0)} seconds\n\n"
        
        text += "=" * 80 + "\n"
        text += "RECOMMENDATIONS\n"
        text += "=" * 80 + "\n\n"
        
        # Generate recommendations based on scores
        if trust_scores['security_score'] < 50:
            text += "🚨 CRITICAL SECURITY RISK\n"
            text += "  - Multiple suspicious patterns detected\n"
            text += "  - Review all flagged imports and strings\n"
            text += "  - Do NOT run this software without verification\n\n"
        
        if trust_scores['transparency_score'] < 50:
            text += "⚠️  LOW TRANSPARENCY\n"
            text += "  - High entropy suggests encryption or packing\n"
            text += "  - Code may be obfuscated\n"
            text += "  - Consider unpacking before further analysis\n\n"
        
        if trust_scores['efficiency_score'] < 60:
            text += "⚠️  RESOURCE INEFFICIENCY\n"
            text += "  - High CPU or memory usage detected\n"
            text += "  - May impact system performance\n"
            text += "  - Monitor during execution\n\n"
        
        if trust_scores['overall_score'] >= 70:
            text += "✅ SOFTWARE MEETS ACCEPTABLE TRUST STANDARDS\n"
            text += "  - Overall score indicates reasonable safety\n"
            text += "  - Still exercise caution with any software\n\n"
        else:
            text += "❌ SOFTWARE DOES NOT MEET RECOMMENDED STANDARDS\n"
            text += "  - Multiple risk factors identified\n"
            text += "  - Thorough investigation recommended\n"
            text += "  - Consider alternative software\n\n"
        
        self.analysis_text.insert('1.0', text)
    
    def _generate_green_insights(self, energy_metrics: Dict, trust_scores: Dict) -> str:
        """Generate green computing insights"""
        text = "🌱 GREEN COMPUTING ANALYSIS\n"
        text += "=" * 80 + "\n\n"
        
        energy_score = trust_scores.get('energy_score', 0)
        total_energy = energy_metrics.get('total_energy_j', 0)
        co2 = energy_metrics.get('co2_grams', 0)
        waste = energy_metrics.get('energy_waste_j', 0)
        
        # Overall assessment
        if energy_score >= 80:
            text += "✅ GREEN SOFTWARE DETECTED\n\n"
        elif energy_score >= 50:
            text += "⚠️  MODERATE ENERGY USAGE\n\n"
        else:
            text += "🚨 HIGH ENERGY WASTE DETECTED\n\n"
        
        text += f"Total Energy: {total_energy:.1f} J\n"
        text += f"Energy Waste: {waste:.1f} J\n"
        text += f"CO2 Emissions: {co2:.4f} g\n"
        text += f"Efficiency: {energy_metrics.get('efficiency_score', 0)}/100\n\n"
        
        text += f"Device: {DEVICE_MODEL}\n"
        text += f"Baseline: {IDLE_W_BASELINE:.1f} W\n"
        
        return text
        
    def _plot_trust_scores(self, trust_scores: Dict):
        """Plot trust scores"""
        self.trust_fig.clear()
        
        ax = self.trust_fig.add_subplot(1, 1, 1)
        
        categories = ['Transparency', 'Security', 'Efficiency', 'Sustainability', 'RE Quality', 'Energy/Green', 'Overall']
        scores = [
            trust_scores['transparency_score'],
            trust_scores['security_score'],
            trust_scores['efficiency_score'],
            trust_scores['sustainability_score'],
            trust_scores['re_quality_score'],
            trust_scores['energy_score'],
            trust_scores['overall_score']
        ]
        
        colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6', '#27ae60', '#1abc9c']
        
        bars = ax.barh(categories, scores, color=colors, alpha=0.7, edgecolor='black', linewidth=1.5)
        
        for i, (bar, score) in enumerate(zip(bars, scores)):
            ax.text(score + 2, i, f'{score}/100', va='center', fontweight='bold')
        
        ax.set_xlabel('Score', fontweight='bold', fontsize=12)
        ax.set_title('Trust & Quality Scores', fontweight='bold', fontsize=14)
        ax.set_xlim(0, 110)
        ax.grid(True, alpha=0.3, axis='x')
        
        ax.axvline(x=85, color='green', linestyle='--', alpha=0.5, label='Excellent')
        ax.axvline(x=70, color='orange', linestyle='--', alpha=0.5, label='Good')
        ax.axvline(x=55, color='red', linestyle='--', alpha=0.5, label='Fair')
        ax.legend(loc='lower right')
        
        self.trust_fig.tight_layout()
        self.trust_canvas.draw()
        
        rating = trust_scores['rating']
        overall = trust_scores['overall_score']
        self.trust_summary_label.config(text=f"Overall Trust Score: {overall}/100 - Rating: {rating}")
        
    def generate_report(self):
        """Generate comprehensive report"""
        if not self.analysis_results:
            messagebox.showwarning("No Analysis", "Please perform an analysis first")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("Text Files", "*.txt")]
        )
        
        if filename:
            try:
                trust_scores = TrustScoreCalculator.calculate_trust_score(
                    self.analysis_results,
                    self.monitor.calculate_summary()
                )
                
                report_data = {
                    'file_info': self.analysis_results['file_info'],
                    'analysis_results': self.analysis_results,
                    'resource_metrics': self.monitor.calculate_summary(),
                    'trust_scores': trust_scores,
                    'timestamp': datetime.now().isoformat()
                }
                
                with open(filename, 'w') as f:
                    json.dump(report_data, f, indent=2)
                
                messagebox.showinfo("Success", f"Report saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {e}")
                
    def export_data(self):
        """Export raw analysis data"""
        if not self.analysis_results:
            messagebox.showwarning("No Analysis", "Please perform an analysis first")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.analysis_results, f, indent=2)
                
                messagebox.showinfo("Success", f"Data exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")
                
    def update_status(self, message: str, color: str = "black"):
        """Update status label"""
        self.status_label.config(text=message, foreground=color)
    
    def start_process_monitoring(self):
        """Start continuous process monitoring"""
        # Only refresh if monitoring is enabled
        if self.monitor_running.get():
            self.refresh_processes()
        
        # Schedule next update (every 5 seconds to reduce lag)
        self.process_update_job = self.root.after(5000, self.start_process_monitoring)
    
    def toggle_monitoring(self):
        """Toggle automatic process monitoring on/off"""
        if self.monitor_running.get():
            self.update_status("Process monitoring enabled", "green")
        else:
            self.update_status("Process monitoring paused", "orange")
    
    def on_tab_changed(self, event):
        """Handle tab change events and optimize resource usage"""
        try:
            current_tab = self.notebook.tab(self.notebook.select(), "text")
            
            # Start/stop process monitoring based on tab
            if "Process Monitor" in current_tab:
                if not self.process_update_job:
                    self.monitor_running.set(True)
                    self.start_process_monitoring()
            else:
                # Stop process monitoring when on other tabs to reduce lag
                if self.process_update_job:
                    self.root.after_cancel(self.process_update_job)
                    self.process_update_job = None
            
            # Start/stop energy monitoring based on tab
            if "Energy" in current_tab:
                if not self.energy_update_job:
                    self.update_live_energy_display()
            else:
                # Stop energy monitoring when not on energy tab
                if hasattr(self, 'energy_update_job') and self.energy_update_job:
                    self.root.after_cancel(self.energy_update_job)
                    self.energy_update_job = None
        except:
            pass
    
    def refresh_processes(self):
        """Refresh process list in background thread"""
        def refresh_thread():
            try:
                processes = self.monitor.get_running_processes()
                
                # Schedule GUI update in main thread
                self.root.after(0, lambda: self._update_process_tree(processes))
                
            except Exception as e:
                print(f"Error refreshing processes: {e}")
        
        # Run in background thread to prevent blocking
        threading.Thread(target=refresh_thread, daemon=True).start()
    
    def _update_process_tree(self, processes):
        """Update process tree in main GUI thread"""
        try:
            # Clear existing items
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)
            
            # Filter processes
            filter_mode = self.process_filter_var.get()
            
            high_risk_count = 0
            critical_count = 0
            
            # Limit to top 50 processes to improve performance
            processes = processes[:50]
            
            for proc in processes:
                # Apply filter
                if filter_mode == 'high' and proc['risk_level'] not in ['HIGH', 'CRITICAL']:
                    continue
                elif filter_mode == 'critical' and proc['risk_level'] != 'CRITICAL':
                    continue
                
                # Count high risk
                if proc['risk_level'] in ['HIGH', 'CRITICAL']:
                    high_risk_count += 1
                if proc['risk_level'] == 'CRITICAL':
                    critical_count += 1
                
                # Determine tag for color
                tag = proc['risk_level'].lower()
                
                # Insert into tree
                values = (
                    proc['pid'],
                    proc['name'],
                    proc['cpu'],
                    proc['memory'],
                    proc['risk_score'],
                    proc['risk_level'],
                    proc['risk_factors'],
                    proc['username']
                )
                
                self.process_tree.insert('', 'end', values=values, tags=(tag,))
            
            # Update labels
            self.process_count_label.config(text=f"Processes: {len(processes)} (Top 50)")
            self.high_risk_label.config(text=f"High Risk: {high_risk_count} (Critical: {critical_count})")
            
        except Exception as e:
            print(f"Error updating process tree: {e}")
    
    def browse_scan_directory(self):
        """Browse for directory to scan"""
        directory = filedialog.askdirectory(
            title="Select Directory to Scan",
            initialdir=str(Path.home())
        )
        
        if directory:
            self.scan_dir_var.set(directory)
    
    def start_directory_scan(self):
        """Start scanning directory"""
        directory = self.scan_dir_var.get()
        
        if not os.path.exists(directory):
            messagebox.showerror("Error", "Directory does not exist!")
            return
        
        self.scan_status_label.config(text="🔍 Scanning...", fg='orange')
        self.root.update()
        
        # Run scan in thread
        def scan_thread():
            try:
                results = self.scanner.scan_directory(directory, max_files=100)
                self.root.after(0, lambda: self.display_scan_results(results))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
                self.scan_status_label.config(text="Scan failed", fg='red')
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def display_scan_results(self, results: List[Dict]):
        """Display directory scan results"""
        # Clear tree
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)
        
        critical_count = 0
        high_count = 0
        
        for file_info in results:
            if file_info['risk_level'] == 'CRITICAL':
                critical_count += 1
            elif file_info['risk_level'] == 'HIGH':
                high_count += 1
            
            # Determine tag
            tag = file_info['risk_level'].lower()
            
            values = (
                file_info['filename'],
                file_info['path'],
                file_info['size_mb'],
                file_info['extension'],
                file_info['entropy'],
                file_info['risk_score'],
                file_info['risk_level'],
                file_info['risk_factors'],
                file_info['modified']
            )
            
            self.scan_tree.insert('', 'end', values=values, tags=(tag,))
        
        # Update labels
        self.scan_files_label.config(text=f"Files Scanned: {len(results)}")
        self.scan_critical_label.config(text=f"Critical: {critical_count}")
        self.scan_high_label.config(text=f"High: {high_count}")
        self.scan_status_label.config(text=f"✅ Scan complete - {len(results)} files", fg='green')
    
    def update_scan_display(self):
        """Update scan display based on filter"""
        # Re-display with current filter
        if hasattr(self.scanner, 'scan_results') and self.scanner.scan_results:
            self.display_scan_results(self.scanner.scan_results)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = TransparencyAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

