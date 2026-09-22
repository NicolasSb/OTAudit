#!/usr/bin/env python3
"""Regenerate samples/demo.pcap."""

from pathlib import Path

from otaudit.synthesis import build_sample_capture

if __name__ == "__main__":
    target = Path(__file__).resolve().parent.parent / "samples" / "demo.pcap"
    build_sample_capture(target)
    print(f"wrote {target} ({target.stat().st_size} bytes)")
