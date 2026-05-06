# XApp/XApp_Normal.py
"""
正常 xApp 模擬模組

模擬一個正常的 xApp 執行完整的 E2 會話流程：
1. E2 Setup：建立與 RIC 的連接
2. RIC Subscription：訂閱 RAN 功能（如 KPM）
3. 週期性 Indication：定期上報 KPI 指標
4. Control Request：發送控制指令
5. Reset：清理連接

此模組演示合法的 E2 交互模式，應該完全通過 FSM 驗證。
"""

import socket, json, time, random, logging

# 配置日誌
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [XApp-Normal] %(message)s"
)

# 連接到攔截器的主機和端口
INTERCEPTOR_HOST = "interceptor"
INTERCEPTOR_PORT = 36422


def send_recv(sock: socket.socket, msg_type: str, payload: dict = None) -> dict:
    """
    發送訊息並接收回應

    Args:
        sock (socket.socket): 連接到攔截器的 socket
        msg_type (str): 訊息類型
        payload (dict): 訊息負載

    Returns:
        dict: 攔截器/RIC 的回應
    """
    if payload is None:
        payload = {}
    # 構建 E2 訊息
    msg = {
        "msg_type": msg_type,
        "src": "xapp_normal",      # 標記為正常 xApp
        "dst": "ric",
        "payload": payload,
        "timestamp": time.time(),
    }
    # 發送訊息
    sock.sendall(json.dumps(msg).encode())
    # 接收回應
    raw = sock.recv(65535)
    resp = json.loads(raw)
    # 記錄訊息交換
    logging.info(f"  → {msg_type:30s} ← {resp.get('msg_type', '?')}")
    return resp


def connect_with_retry(host: str, port: int, retries: int = 10, delay: float = 2.0) -> socket.socket:
    """
    帶有重試的連接函數

    等待攔截器啟動並就緒。在 Docker 環境中，服務啟動需要時間。

    Args:
        host (str): 目標主機
        port (int): 目標端口
        retries (int): 最大重試次數
        delay (float): 重試間隔（秒）

    Returns:
        socket.socket: 已連接的 socket

    Raises:
        RuntimeError: 無法連接到目標
    """
    for attempt in range(1, retries + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            logging.info(f"Connected to interceptor at {host}:{port}")
            return s
        except OSError:
            logging.warning(f"Interceptor not ready, retry {attempt}/{retries} ...")
            time.sleep(delay)
    raise RuntimeError(f"Could not connect to {host}:{port} after {retries} retries")


def run():
    """
    執行正常的 E2 會話流程

    流程遵循合法的狀態轉換：
    IDLE → SETUP → ACTIVE (多條 Indication) → ACTIVE (Control) → IDLE
    """
    logging.info("Starting normal E2 session")

    with connect_with_retry(INTERCEPTOR_HOST, INTERCEPTOR_PORT) as s:

        # ── Step 1: E2 Setup ──────────────────────────────────────────
        # xApp 請求與 RIC 建立連接
        # 狀態轉換：IDLE → SETUP
        logging.info("[Step 1] Sending E2 Setup Request")
        resp = send_recv(s, "E2SetupRequest", {
            "gnb_id": "gnb-001",      # gNodeB 標識符
            "plmn": "00101",          # 公網移動網絡代碼
        })
        if resp.get("msg_type") != "E2SetupResponse":
            logging.error(f"Setup rejected: {resp}")
            return

        # ── Step 2: RIC Subscription ──────────────────────────────────
        # xApp 訂閱 RAN 功能（如 KPM - Key Performance Measurement）
        # 狀態轉換：SETUP → ACTIVE
        logging.info("[Step 2] Sending RIC Subscription Request")
        resp = send_recv(s, "RICsubscriptionRequest", {
            "ran_function_id": 1,        # RAN 功能 ID
            "action_type": "report",     # 動作類型：定期報告
            "report_period_ms": 1000,    # 報告週期（毫秒）
        })
        if resp.get("msg_type") != "RICsubscriptionResponse":
            logging.error(f"Subscription rejected: {resp}")
            return

        # 提取訂閱 ID 以在後續訊息中使用
        sub_id = resp.get("payload", {}).get("subscription_id", "unknown")
        logging.info(f"Subscription granted: {sub_id}")

        # ── Step 3: Periodic KPI Indications ─────────────────────────
        # xApp 定期上報 KPI 指標
        # 狀態保持：ACTIVE → ACTIVE
        logging.info("[Step 3] Sending periodic KPI Indications")
        for i in range(10):
            # 模擬不同的 KPI 值（40-95 之間）
            kpi = round(random.uniform(40.0, 95.0), 2)
            send_recv(s, "RICindication", {
                "subscription_id": sub_id,  # 對應的訂閱 ID
                "indication_type": "report",
                "kpi_value": kpi,           # KPI 值
                "seq": i,                   # 序列號
            })
            time.sleep(0.5)  # 每 500ms 發送一次

        # ── Step 4: Control Request ───────────────────────────────────
        # xApp 發送控制指令給 RAN
        # 狀態保持：ACTIVE → ACTIVE
        logging.info("[Step 4] Sending RIC Control Request")
        send_recv(s, "RICcontrolRequest", {
            "control_type": "handover",      # 控制類型：切換
            "target_cell": "cell-002",       # 目標小區
        })

        # ── Step 5: Clean Reset ───────────────────────────────────────
        # xApp 請求重置連接
        # 狀態轉換：ACTIVE → IDLE
        logging.info("[Step 5] Sending Reset Request")
        send_recv(s, "ResetRequest", {})

    logging.info("Normal session completed successfully")


if __name__ == "__main__":
    # 執行正常的 E2 會話
    run()
