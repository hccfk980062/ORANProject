# Near-RT_RIC/RICNode.py
"""
Near-RT RIC 節點模擬模組

實現 Near Real-Time RAN Intelligent Controller 的核心功能：
- 管理與多個 xApp 的連接
- 處理 E2 訊息並維護會話狀態
- 提供 RAN 控制和協調功能
"""

import socket
import json
import logging
import time
import threading
from datetime import datetime

# 配置日誌：記錄 RIC 的所有操作
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [RIC] %(levelname)s %(message)s"
)

# ──────────────────────────────────────────
# RIC 對每種 E2 訊息的標準回應範本
# ──────────────────────────────────────────
# 這些模板定義了 RIC 對不同訊息類型的標準回應格式
RESPONSE_MAP = {
    "E2SetupRequest": {
        # E2 Setup 回應：確認 RIC 已準備好與 xApp 通信
        "msg_type": "E2SetupResponse",
        "payload": {
            "global_ric_id": "ric-node-001",  # RIC 全局標識符
            "ran_functions_accepted": ["KPM", "RC", "CCC"],  # 支持的 RAN 功能
            "status": "success"
        }
    },
    "RICsubscriptionRequest": {
        # 訂閱回應：授予 xApp 的訂閱請求
        "msg_type": "RICsubscriptionResponse",
        "payload": {
            "subscription_id": None,   # 動態填入
            "admitted_actions": ["report", "insert"],  # 允許的動作
            "status": "success"
        }
    },
    "RICindication": {
        # Indication 確認：收到 KPI 指標
        "msg_type": "RICindicationAck",
        "payload": {"status": "received"}
    },
    "RICcontrolRequest": {
        # 控制確認：確認控制指令已執行
        "msg_type": "RICcontrolAcknowledge",
        "payload": {"status": "control_applied"}
    },
    "ResetRequest": {
        # 重置確認：確認會話已重置
        "msg_type": "ResetResponse",
        "payload": {"status": "reset_ok"}
    },
}


class NearRTRIC:
    """
    Near-RT RIC 節點類

    模擬 O-RAN Near Real-Time RAN Intelligent Controller：
    - 監聽 xApp 的連接
    - 管理 xApp 的註冊和訂閱
    - 處理 E2 訊息
    - 維護 RAN 功能和資源狀態
    """

    def __init__(self, host="0.0.0.0", port=36421):
        """
        初始化 RIC 節點

        Args:
            host (str): 監聽的主機地址
            port (int): 監聽的端口
        """
        self.host = host
        self.port = port

        # 追蹤已知的 xApp session（基於連接地址）
        self.registered_xapps: dict[str, dict] = {}

        # 簡易統計
        self.stats = {
            "total_received": 0,      # 接收的總訊息數
            "by_type": {},            # 按訊息類型統計
            "errors": 0,              # 錯誤訊息數
        }

    # ──────────────────────────────────────
    # 主迴圈
    # ──────────────────────────────────────
    def start(self):
        """
        啟動 RIC 主迴圈

        監聽 xApp 連接，為每條連接創建獨立執行緒處理。
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(10)  # 最多同時等待 10 個連接
            logging.info(f"Near-RT RIC listening on {self.host}:{self.port}")

            while True:
                # 接受 xApp 連接
                conn, addr = srv.accept()
                # 每條連線用獨立執行緒處理，模擬並發 xApp
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr),
                    daemon=True
                )
                t.start()

    # ──────────────────────────────────────
    # 連線處理
    # ──────────────────────────────────────
    def _handle_connection(self, conn: socket.socket, addr: tuple):
        """
        處理單個 xApp 連接

        Args:
            conn (socket.socket): 與 xApp 的連接 socket
            addr (tuple): xApp 的地址 (IP, PORT)
        """
        session_key = f"{addr[0]}:{addr[1]}"
        logging.info(f"New connection from {session_key}")

        with conn:
            while True:
                try:
                    # 接收訊息
                    raw = conn.recv(65535)
                    if not raw:
                        break  # xApp 關閉連接

                    # 解析並處理訊息
                    msg = json.loads(raw.decode())
                    response = self._process_message(msg, session_key)

                    # 發送回應
                    conn.send(json.dumps(response).encode())

                except json.JSONDecodeError:
                    # JSON 解析失敗
                    self.stats["errors"] += 1
                    logging.warning(f"Malformed JSON from {session_key}")
                    # 回傳錯誤回應
                    conn.send(json.dumps({
                        "msg_type": "Error",
                        "payload": {"reason": "invalid_json"}
                    }).encode())

                except ConnectionResetError:
                    break

        logging.info(f"Connection closed: {session_key}")

    # ──────────────────────────────────────
    # 訊息處理邏輯
    # ──────────────────────────────────────
    def _process_message(self, msg: dict, session_key: str) -> dict:
        """
        處理傳入的 E2 訊息

        Args:
            msg (dict): E2 訊息
            session_key (str): 會話標識符

        Returns:
            dict: RIC 的回應訊息
        """
        msg_type = msg.get("msg_type", "Unknown")
        src = msg.get("src", "unknown")

        # 更新統計
        self.stats["total_received"] += 1
        self.stats["by_type"][msg_type] = self.stats["by_type"].get(msg_type, 0) + 1

        logging.info(f"  ← RECV [{msg_type}] from {src}")

        # 根據訊息類型執行對應的處理方法
        if msg_type == "E2SetupRequest":
            return self._handle_setup(msg, session_key)

        elif msg_type == "RICsubscriptionRequest":
            return self._handle_subscription(msg, session_key)

        elif msg_type == "RICindication":
            return self._handle_indication(msg, session_key)

        elif msg_type == "RICcontrolRequest":
            return self._handle_control(msg, session_key)

        elif msg_type == "ResetRequest":
            return self._handle_reset(msg, session_key)

        else:
            # 未知的訊息類型
            logging.warning(f"  Unknown message type: {msg_type}")
            self.stats["errors"] += 1
            return {
                "msg_type": "Error",
                "payload": {"reason": f"unknown_type: {msg_type}"}
            }

    # ──────────────────────────────────────
    # 各訊息類型的具體處理
    # ──────────────────────────────────────
    def _handle_setup(self, msg: dict, session_key: str) -> dict:
        """
        處理 E2 Setup 請求

        E2 Setup 是 xApp 與 RIC 之間建立連接的第一步。
        RIC 確認連接並返回 RIC 標識符。

        Args:
            msg (dict): Setup 請求訊息
            session_key (str): 會話標識符

        Returns:
            dict: Setup 回應
        """
        # 記錄 xApp 的資訊
        xapp_info = {
            "src": msg.get("src"),
            "registered_at": datetime.now().isoformat(),
            "subscriptions": [],  # 此 xApp 的訂閱列表
        }
        self.registered_xapps[session_key] = xapp_info
        logging.info(f"  ✔ xApp registered: {msg.get('src')}")

        # 構建並返回回應
        resp = RESPONSE_MAP["E2SetupRequest"].copy()
        resp["dst"] = msg.get("src")
        resp["timestamp"] = time.time()
        return resp

    def _handle_subscription(self, msg: dict, session_key: str) -> dict:
        """
        處理 RIC Subscription 請求

        xApp 通過此訊息訂閱 RAN 功能（如 KPM），並設定報告參數。

        Args:
            msg (dict): Subscription 請求訊息
            session_key (str): 會話標識符

        Returns:
            dict: Subscription 回應
        """
        # 為此訂閱分配唯一 ID
        sub_id = f"sub-{int(time.time()*1000)}"

        # 記錄訂閱信息
        if session_key in self.registered_xapps:
            self.registered_xapps[session_key]["subscriptions"].append(sub_id)

        logging.info(f"  ✔ Subscription granted: {sub_id}")

        # 構建並返回回應，填入訂閱 ID
        resp = json.loads(json.dumps(RESPONSE_MAP["RICsubscriptionRequest"]))  # 深複制
        resp["payload"]["subscription_id"] = sub_id
        resp["dst"] = msg.get("src")
        resp["timestamp"] = time.time()
        return resp

    def _handle_indication(self, msg: dict, session_key: str) -> dict:
        """
        處理 RIC Indication 訊息

        xApp 通過此訊息定期上報 KPI 指標（如射頻功率、負載等）。
        RIC 接收指標數據並進行實時分析。

        Args:
            msg (dict): Indication 訊息
            session_key (str): 會話標識符

        Returns:
            dict: Indication 確認
        """
        payload = msg.get("payload", {})

        # 模擬 RIC 對數據的簡單分析
        kpi = payload.get("kpi_value")
        if kpi is not None:
            logging.info(f"  📊 KPI received: {kpi}")
            # 根據 KPI 值判斷是否需要觸發控制動作
            if kpi > 90:
                logging.warning(f"  ⚠ High KPI alert: {kpi}")

        # 返回確認
        resp = RESPONSE_MAP["RICindication"].copy()
        resp["dst"] = msg.get("src")
        resp["timestamp"] = time.time()
        return resp

    def _handle_control(self, msg: dict, session_key: str) -> dict:
        """
        處理 RIC Control 請求

        xApp 通過此訊息發送控制指令給 RAN（如切換、功率控制等）。
        RIC 執行相應的網路控制動作。

        Args:
            msg (dict): Control 請求訊息
            session_key (str): 會話標識符

        Returns:
            dict: Control 確認
        """
        control_type = msg.get("payload", {}).get("control_type", "unknown")
        logging.info(f"  🎛  Control applied: type={control_type}")

        # 返回確認
        resp = RESPONSE_MAP["RICcontrolRequest"].copy()
        resp["dst"] = msg.get("src")
        resp["payload"]["control_type"] = control_type
        resp["timestamp"] = time.time()
        return resp

    def _handle_reset(self, msg: dict, session_key: str) -> dict:
        """
        處理 Reset 請求

        xApp 通過此訊息請求重置連接，清除所有訂閱和狀態。

        Args:
            msg (dict): Reset 請求訊息
            session_key (str): 會話標識符

        Returns:
            dict: Reset 確認
        """
        # 清除該 session 的記錄
        if session_key in self.registered_xapps:
            del self.registered_xapps[session_key]
            logging.info(f"  🔄 Session reset: {session_key}")

        # 返回確認
        resp = RESPONSE_MAP["ResetRequest"].copy()
        resp["dst"] = msg.get("src")
        resp["timestamp"] = time.time()
        return resp

    # ──────────────────────────────────────
    # 定期統計報告（可選）
    # ──────────────────────────────────────
    def _print_stats_loop(self, interval=30):
        """
        在背景定期列印統計資訊

        Args:
            interval (int): 統計輸出間隔（秒）
        """
        while True:
            time.sleep(interval)
            logging.info(
                f"[STATS] total={self.stats['total_received']} "
                f"errors={self.stats['errors']} "
                f"xapps={len(self.registered_xapps)} "
                f"by_type={self.stats['by_type']}"
            )


if __name__ == "__main__":
    # 建立 RIC 實例
    ric = NearRTRIC()

    # 背景執行統計輸出
    t = threading.Thread(target=ric._print_stats_loop, args=(30,), daemon=True)
    t.start()

    # 啟動 RIC 主迴圈
    ric.start()