# FSM_Interceptor/Metrics.py
"""
性能指標收集模組

收集並分析攔截器的性能數據，包括：
- 訊息允許/阻止率
- 訊息處理延遲
- 詳細的訊息日誌
"""

import json, time
from collections import defaultdict


class MetricsCollector:
    """
    性能指標收集器

    記錄每條訊息的處理結果和延遲時間，最後生成統計報告。
    """

    def __init__(self, log_path="/app/logs/results.jsonl"):
        """
        初始化指標收集器

        Args:
            log_path (str): 指標日誌檔案路徑（JSONL 格式）
        """
        self.log_path = log_path  # 持久化日誌檔案路徑
        self.window = []  # 訊息緩衝區（記憶體中的最近訊息）

    def record(self, session_id, msg_type, allowed, latency_ms):
        """
        記錄單條訊息的處理結果

        Args:
            session_id (str): 會話標識符
            msg_type (str): 訊息類型
            allowed (bool): 訊息是否被允許通過
            latency_ms (float): 處理此訊息的延遲（毫秒）
        """
        # 構建指標記錄
        entry = {
            "ts": time.time(),           # 時間戳
            "session": session_id,        # 會話 ID
            "type": msg_type,            # 訊息類型
            "allowed": allowed,          # 是否允許
            "latency_ms": latency_ms     # 延遲（毫秒）
        }
        # 添加到記憶體緩衝區
        self.window.append(entry)
        # 同時持久化到檔案
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def report(self):
        """
        生成統計報告

        計算並列印此會話的統計數據，包括：
        - 總訊息數
        - 阻止率
        - 平均延遲
        """
        total = len(self.window)
        blocked = sum(1 for e in self.window if not e["allowed"])
        avg_lat = sum(e["latency_ms"] for e in self.window) / max(total, 1)
        # 列印統計摘要
        print(f"總請求: {total} | 攔截率: {blocked/total:.1%} | 平均延遲: {avg_lat:.2f}ms")