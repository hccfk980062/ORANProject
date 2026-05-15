#!/usr/bin/env python3
# analyze_results.py
"""
O-RAN FSM 攔截器安全實驗結果分析腳本

讀取 logs/results.jsonl 並生成完整評估報告，對應論文指標：
  - 攔截成功率（Interception Success Rate）
  - 各攻擊類型的防禦效果
  - 攔截器系統運算開銷（平均/最大延遲）
  - 各 Session 行為分析

用法：
  python analyze_results.py                    # 讀取預設路徑 logs/results.jsonl
  python analyze_results.py <path/to/results.jsonl>
"""

import json
import sys
from collections import defaultdict
from pathlib import Path


def load_records(path: str) -> list[dict]:
    records = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  [warn] line {lineno} skipped: {e}", file=sys.stderr)
    return records


def analyze(records: list[dict]) -> None:
    total = len(records)
    if total == 0:
        print("No records found in log file.")
        return

    blocked  = sum(1 for r in records if not r.get("allowed", True))
    allowed  = total - blocked
    lat_vals = [r.get("latency_ms", 0.0) for r in records]
    avg_lat  = sum(lat_vals) / total
    max_lat  = max(lat_vals)
    min_lat  = min(lat_vals)

    by_type:   dict[str, dict]  = defaultdict(lambda: {"total": 0, "blocked": 0, "lat_sum": 0.0})
    by_reason: dict[str, int]   = defaultdict(int)
    by_session: dict[str, dict] = defaultdict(lambda: {"total": 0, "blocked": 0})

    for r in records:
        t   = r.get("type", "Unknown")
        sid = r.get("session", "?")
        lat = r.get("latency_ms", 0.0)

        by_type[t]["total"]   += 1
        by_type[t]["lat_sum"] += lat
        by_session[sid]["total"] += 1

        if not r.get("allowed", True):
            by_type[t]["blocked"]    += 1
            by_session[sid]["blocked"] += 1
            reason = r.get("reason") or "fsm_violation"
            by_reason[reason]        += 1

    # ── 總覽 ──────────────────────────────────────────────────────────────────
    print()
    print("=" * 62)
    print("   O-RAN FSM 攔截器 — 安全實驗評估報告")
    print("=" * 62)
    print(f"\n{'【總覽】':}")
    print(f"  總訊息數          : {total}")
    print(f"  允許通過          : {allowed:>6}  ({allowed/total:>6.1%})")
    print(f"  攔截數量          : {blocked:>6}  ({blocked/total:>6.1%})")
    print(f"  攔截成功率        : {blocked/total:>6.1%}")
    print(f"\n  平均處理延遲      : {avg_lat:.4f} ms")
    print(f"  最大處理延遲      : {max_lat:.4f} ms")
    print(f"  最小處理延遲      : {min_lat:.4f} ms")

    # ── 各訊息類型攔截統計 ────────────────────────────────────────────────────
    print(f"\n{'【各訊息類型攔截統計】':}")
    header = f"  {'訊息類型':<30} {'總數':>5} {'攔截':>5} {'攔截率':>7} {'平均延遲':>10}"
    print(header)
    print(f"  {'─'*58}")
    for t, stat in sorted(by_type.items(), key=lambda x: -x[1]["blocked"]):
        n   = stat["total"]
        b   = stat["blocked"]
        lat = stat["lat_sum"] / n
        bar = "█" * int(b / n * 20)
        print(f"  {t:<30} {n:>5} {b:>5} {b/n:>7.1%} {lat:>9.4f}ms  {bar}")

    # ── 攔截原因分佈 ──────────────────────────────────────────────────────────
    print(f"\n{'【攔截原因分佈】':}")
    reason_labels = {
        "rate_limit":    "速率超限 (DoS Flooding)",
        "malformed":     "畸形封包 (Malformed Packet)",
        "fsm_violation": "狀態機違規 (FSM Violation)",
    }
    for reason, count in sorted(by_reason.items(), key=lambda x: -x[1]):
        label = reason_labels.get(reason, reason)
        pct   = count / blocked if blocked else 0
        bar   = "█" * int(pct * 30)
        print(f"  {label:<35} {count:>5} 次  ({pct:.1%})  {bar}")

    # ── 各 Session 行為分析 ───────────────────────────────────────────────────
    print(f"\n{'【各 Session 行為分析】':}")
    print(f"  {'Session':<26} {'總數':>5} {'攔截':>5} {'攔截率':>7}  {'研判'}")
    print(f"  {'─'*60}")
    for sid, stat in sorted(by_session.items(), key=lambda x: -x[1]["blocked"]):
        n       = stat["total"]
        b       = stat["blocked"]
        rate    = b / n
        verdict = "⚠ 惡意/異常" if rate >= 0.5 else ("✓ 正常" if rate == 0 else "? 可疑")
        print(f"  {sid:<26} {n:>5} {b:>5} {rate:>7.1%}  {verdict}")

    print()
    print("=" * 62)
    print("  結論：FSM 攔截器對違規訊息的攔截成功率  =", f"{blocked/total:.1%}")
    print("        平均每條訊息攔截處理延遲          =", f"{avg_lat:.4f} ms")
    print("=" * 62)
    print()


if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else "logs/results.jsonl"
    p = Path(log_path)
    if not p.exists():
        print(f"Error: '{log_path}' not found.")
        print("  Hint: run 'docker compose up' first, then re-run this script.")
        sys.exit(1)

    records = load_records(str(p))
    print(f"Loaded {len(records)} records from '{log_path}'")
    analyze(records)
