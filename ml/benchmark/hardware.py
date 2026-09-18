"""
Host Hardware Profile Discovery for ULPF-X Performance Benchmarks.
Captures reference hardware specifications empirically from the host environment.
"""

from __future__ import annotations

import os
import platform
from typing import Any, Dict


def get_cpu_model() -> str:
    """Discovers host CPU model name from /proc/cpuinfo or platform."""
    try:
        if os.path.exists("/proc/cpuinfo"):
            with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "model name" in line:
                        parts = line.split(":", 1)
                        if len(parts) > 1 and parts[1].strip():
                            return parts[1].strip()
    except Exception:
        pass

    # Fallback to platform processor or machine
    proc = platform.processor() or platform.machine()
    return proc if proc else "Unknown x86_64 CPU"


def get_total_memory_mb() -> float:
    """Discovers host total RAM in megabytes."""
    try:
        import psutil
        return round(float(psutil.virtual_memory().total) / (1024.0 * 1024.0), 2)
    except Exception:
        pass

    try:
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            kb = float(parts[1])
                            return round(kb / 1024.0, 2)
    except Exception:
        pass

    return 4096.0  # Safe default baseline


def get_hardware_profile() -> Dict[str, Any]:
    """
    Captures complete host hardware profile matching benchmark_report.schema.json.
    """
    cores = os.cpu_count() or 1
    return {
        "cpu_model": get_cpu_model(),
        "cpu_cores": int(cores),
        "memory_total_mb": get_total_memory_mb(),
        "os_platform": platform.platform() or "Linux",
        "python_version": platform.python_version(),
    }
