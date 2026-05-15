# FSM_Interceptor/Metrics.py
"""
性能指標收集模組

收集並分析攔截器的性能數據，包括：
- 訊息允許/阻止率
- 攔截原因分佈（速率超限、畸形封包、FSM 違規）
- 訊息處理延遲
- 各 session 統計
"""

import json, time
from collections import defaultdict


class MetricsCollector:
    """
    性能指標收集器

    記錄每條訊息的處理結果、延遲時間與阻止原因，
    session 結束時生成統計報告並持久化摘要。
    """

    def __init__(self, log_path: str = "/app/logs/results.jsonl"):
        self.log_path = log_path
        self.window: list[dict] = []

    def record(
        self,
        session_id: str,
        msg_type: str,
        allowed: bool,
        latency_ms: float,
        reason: str = "",
    ) -> None:
        """
        記錄單條訊息的處理結果。

        Args:
            session_id: 會話標識符
            msg_type:   訊息類型
            allowed:    是否通過攔截器
            latency_ms: 攔截器處理延遲（毫秒）
            reason:     若被阻止，記錄原因（rate_limit / malformed / fsm_violation）
        """
        entry = {
            "ts":         time.time(),
            "session":    session_id,
            "type":       msg_type,
            "allowed":    allowed,
            "latency_ms": latency_ms,
            "reason":     reason,
        }
        self.window.append(entry)
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def report(self) -> None:
        """
        生成並列印此 session 的統計報告，同時將摘要持久化為 JSON。
        """
        total = len(self.window)
        if total == 0:
            return

        blocked = sum(1 for e in self.window if not e["allowed"])
        avg_lat = sum(e["latency_ms"] for e in self.window) / total

        # 各訊息類型的分類統計
        by_type: dict[str, dict] = defaultdict(lambda: {"total": 0, "blocked": 0})
        by_reason: dict[str, int] = defaultdict(int)

        for e in self.window:
            t = e["type"]
            by_type[t]["total"] += 1
            if not e["allowed"]:
                by_type[t]["blocked"] += 1
                by_reason[e.get("reason") or "fsm_violation"] += 1

        print("─" * 55)
        print(f"  攔截器統計報告")
        print("─" * 55)
        print(f"  總請求數 : {total}")
        print(f"  允許通過 : {total - blocked} ({(total-blocked)/total:.1%})")
        print(f"  攔截數量 : {blocked} ({blocked/total:.1%})")
        print(f"  平均延遲 : {avg_lat:.3f} ms")
        if by_reason:
            print(f"  攔截原因 : " + " | ".join(f"{k}={v}" for k, v in by_reason.items()))
        print("─" * 55)

        # 持久化摘要 JSON（供 analyze_results.py 讀取）
        summary_path = self.log_path.replace("results.jsonl", "summary.json")
        try:
            summary = {
                "generated_at":  time.time(),
                "total":         total,
                "allowed":       total - blocked,
                "blocked":       blocked,
                "block_rate":    blocked / total,
                "avg_latency_ms": avg_lat,
                "by_type":       {k: dict(v) for k, v in by_type.items()},
                "by_reason":     dict(by_reason),
            }
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2)
        except OSError:
            pass  # 若 log 目錄未掛載則靜默跳過
