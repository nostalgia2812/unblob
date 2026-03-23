#!/usr/bin/env python3
"""
Ghost AI — Unblob Bridge
Binary / firmware analysis module for Ghost AI dark OSINT.
NO wallet integration.
"""
from __future__ import annotations
import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class ExtractedComponent:
    path: str
    size: int
    mime_type: str
    handler: str
    entropy: float
    is_compressed: bool = False
    is_encrypted: bool = False
    contains_strings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size_bytes": self.size,
            "mime_type": self.mime_type,
            "handler": self.handler,
            "entropy": round(self.entropy, 4),
            "is_compressed": self.is_compressed,
            "is_encrypted": self.is_encrypted,
            "interesting_strings": self.contains_strings[:20],
        }


@dataclass
class FirmwareAnalysis:
    source_file: str
    total_components: int
    high_entropy_count: int  # entropy > 7.5 = possibly encrypted
    components: list[ExtractedComponent]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "source_file": self.source_file,
            "total_components": self.total_components,
            "high_entropy_components": self.high_entropy_count,
            "possibly_encrypted": self.high_entropy_count > 0,
            "timestamp": self.timestamp,
            "components": [c.to_dict() for c in self.components[:50]],
        }


# Interesting strings to extract from firmware
INTERESTING_PATTERNS = [
    "password", "passwd", "secret", "token", "api_key",
    "admin", "root", "backdoor", "debug", "telnet",
    "ssh", "ftp", "http", "/bin/sh", "/bin/bash",
    "wget", "curl", "chmod", "exec", "eval",
    "192.168.", "10.0.", "172.16.",
]


class UnblobBridge:
    """Ghost AI bridge to unblob firmware extraction engine."""

    def __init__(self, unblob_bin: str = "unblob") -> None:
        self.bin = unblob_bin

    def extract(self, firmware_path: str, output_dir: Optional[str] = None) -> FirmwareAnalysis:
        """Extract and analyze a firmware/binary file."""
        src = Path(firmware_path)
        if not src.exists():
            raise FileNotFoundError(f"Firmware not found: {firmware_path}")

        with tempfile.TemporaryDirectory() as tmp_out:
            out_dir = output_dir or tmp_out
            cmd = [self.bin, "-e", out_dir, str(src)]

            try:
                subprocess.run(cmd, capture_output=True, timeout=300)
            except FileNotFoundError:
                return FirmwareAnalysis(
                    source_file=str(src),
                    total_components=0,
                    high_entropy_count=0,
                    components=[],
                )

            components = self._analyze_output(out_dir)

        high_entropy = sum(1 for c in components if c.entropy > 7.5)
        return FirmwareAnalysis(
            source_file=str(src),
            total_components=len(components),
            high_entropy_count=high_entropy,
            components=components,
        )

    def _analyze_output(self, out_dir: str) -> list[ExtractedComponent]:
        components = []
        for path in Path(out_dir).rglob("*"):
            if not path.is_file():
                continue
            size = path.stat().st_size
            entropy = self._calc_entropy(path)
            strings = self._extract_strings(path)
            components.append(ExtractedComponent(
                path=str(path.relative_to(out_dir)),
                size=size,
                mime_type=self._detect_mime(path),
                handler="unblob",
                entropy=entropy,
                is_compressed=entropy > 6.0 and size > 1024,
                is_encrypted=entropy > 7.5,
                contains_strings=strings,
            ))
        return components

    @staticmethod
    def _calc_entropy(path: Path) -> float:
        import math
        try:
            data = path.read_bytes()[:65536]
            if not data:
                return 0.0
            freq = [0] * 256
            for b in data:
                freq[b] += 1
            entropy = 0.0
            n = len(data)
            for f in freq:
                if f > 0:
                    p = f / n
                    entropy -= p * math.log2(p)
            return entropy
        except Exception:
            return 0.0

    @staticmethod
    def _detect_mime(path: Path) -> str:
        try:
            result = subprocess.run(
                ["file", "--mime-type", "-b", str(path)],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip()
        except Exception:
            return "application/octet-stream"

    @staticmethod
    def _extract_strings(path: Path, min_len: int = 8) -> list[str]:
        interesting = []
        try:
            data = path.read_bytes()[:131072]
            text = data.decode("latin-1", errors="replace")
            for pat in INTERESTING_PATTERNS:
                idx = 0
                while True:
                    idx = text.lower().find(pat, idx)
                    if idx == -1:
                        break
                    snippet = text[max(0, idx-10):idx+30].strip()
                    if snippet not in interesting:
                        interesting.append(snippet)
                    idx += len(pat)
        except Exception:
            pass
        return interesting[:20]


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python unblob_bridge.py <firmware_file>")
        sys.exit(1)
    bridge = UnblobBridge()
    analysis = bridge.extract(sys.argv[1])
    print(json.dumps(analysis.to_dict(), indent=2))
