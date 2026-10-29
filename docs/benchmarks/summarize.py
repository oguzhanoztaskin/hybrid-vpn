#!/usr/bin/env python3
"""Summarise a run-emulator.sh results directory as Markdown tables.

    python3 docs/benchmarks/summarize.py docs/benchmarks/raw/<run>
"""
import json
import re
import statistics
import sys
from pathlib import Path

MODES = [("off", "VPN off"), ("dns", "DNS-only (default)"), ("go", "Go full tunnel (M2a)")]


def load(run: Path, mode: str):
    path = run / f"{mode}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def pick(rows, mode, **match):
    return [r for r in rows if r.get("mode") == mode and all(r.get(k) == v for k, v in match.items())]


def med(values, fmt="{:.0f}"):
    values = [v for v in values if v is not None]
    if not values:
        return "—"
    m = statistics.median(values)
    if len(values) > 1:
        return f"{fmt.format(m)} ({fmt.format(min(values))}–{fmt.format(max(values))})"
    return fmt.format(m)


def meminfo(run: Path, mode: str, phase: str):
    path = run / f"{mode}-meminfo-{phase}.txt"
    if not path.exists():
        return {}
    text = path.read_text()
    out = {}
    m = re.search(r"TOTAL PSS:\s+(\d+)", text)
    if m:
        out["pss_mb"] = int(m.group(1)) / 1024
    m = re.search(r"TOTAL RSS:\s+(\d+)", text)
    if m:
        out["rss_mb"] = int(m.group(1)) / 1024
    m = re.search(r"Native Heap:\s+(\d+)", text)
    if m:
        out["native_mb"] = int(m.group(1)) / 1024
    m = re.search(r"Java Heap:\s+(\d+)", text)
    if m:
        out["java_mb"] = int(m.group(1)) / 1024
    m = re.search(r"Private Other:\s+(\d+)", text)
    if m:
        out["other_mb"] = int(m.group(1)) / 1024
    return out


def main(run: Path):
    data = {m: load(run, m) for m, _ in MODES}
    cols = [label for _, label in MODES]
    print("| Metric | " + " | ".join(cols) + " |")
    print("| --- | " + " | ".join("---" for _ in cols) + " |")

    def row(name, fn):
        print(f"| {name} | " + " | ".join(fn(data[m]) for m, _ in MODES) + " |")

    row("TCP download, Mbit/s (median, min–max)", lambda d: med([r.get("mbit_per_s") for r in pick(d, "tcp-down")]))
    row("TCP upload, Mbit/s", lambda d: med([r.get("mbit_per_s") for r in pick(d, "tcp-up")]))
    row("UDP 1200 B burst: offered Mbit/s", lambda d: med([r.get("offered_mbit_per_s") for r in pick(d, "udp")]))
    row("UDP burst: delivered Mbit/s", lambda d: med([r.get("goodput_mbit_per_s") for r in pick(d, "udp")]))
    row("UDP burst: loss %", lambda d: med([r.get("loss_pct") for r in pick(d, "udp")], "{:.1f}"))
    row("TCP handshake p50 / p99, ms", lambda d: "/".join(med([r.get(k) for r in pick(d, "connect")], "{:.1f}") for k in ("handshake_p50_ms", "handshake_p99_ms")))
    row("TCP round trip on open conn p50 / p99, ms", lambda d: "/".join(med([r.get(k) for r in pick(d, "rtt")], "{:.2f}") for k in ("p50_ms", "p99_ms")))
    row("DNS cached p50 / p99, ms", lambda d: "/".join(med([r.get(k) for r in pick(d, "dns", uncached=False)], "{:.2f}") for k in ("p50_ms", "p99_ms")))
    row("DNS uncached p50 / p99, ms", lambda d: "/".join(med([r.get(k) for r in pick(d, "dns", uncached=True)], "{:.1f}") for k in ("p50_ms", "p99_ms")))
    row("Idle CPU, ms per minute (screen off)", lambda d: med([r.get("cpu_ms_per_min") for r in pick(d, "idle")], "{:.1f}"))
    row("Idle voluntary context switches / min", lambda d: med([r.get("voluntary_switches_per_min") for r in pick(d, "idle")], "{:.0f}"))
    row("Idle involuntary context switches / min", lambda d: med([r.get("involuntary_switches_per_min") for r in pick(d, "idle")], "{:.0f}"))
    row("Threads (idle)", lambda d: med([r.get("threads") for r in pick(d, "idle")]))
    for phase in ("start", "load", "idle"):
        print(f"| Memory {phase}: PSS / native heap / private other, MB | " + " | ".join(
            (lambda mi: f"{mi.get('pss_mb', 0):.0f} / {mi.get('native_mb', 0):.0f} / {mi.get('other_mb', 0):.0f}" if mi else "—")(meminfo(run, m, phase))
            for m, _ in MODES) + " |")
    row("Wi-Fi off → new connection works, ms", lambda d: med([r.get("wifi_off_to_connect_ms") for r in pick(d, "transition")]))
    row("Wi-Fi off → DNS works, ms", lambda d: med([r.get("wifi_off_to_dns_ms") for r in pick(d, "transition")]))
    row("Bulk transfer across Wi-Fi off", lambda d: ", ".join(
        ("completed" if not r["bulk_flow"].get("error") else f"broke ({r['bulk_flow']['error']}) after {r['bulk_flow'].get('bytes', 0) / 1e6:.0f} MB")
        for r in pick(d, "transition")) or "—")
    row("Tunnel up on cellular / after Wi-Fi back", lambda d: ", ".join(
        f"{r.get('tun_up_on_cellular')} / {r.get('tun_up_after')}" for r in pick(d, "transition")) or "—")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
