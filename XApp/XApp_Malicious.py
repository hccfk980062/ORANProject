# XApp/XApp_Malicious.py
"""
惡意 xApp 模擬模組

DoS 攻擊：跳過 Setup 直接發送大量異常訊息

此模組用於安全測試和防禦驗證，目的是測試 FSM 攔截器的偵測能力。
"""

import socket, json, time, random, logging

# 配置日誌
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [XApp-Malicious] %(message)s"
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
        dict: 攔截器的回應
    """
    if payload is None:
        payload = {}
    # 構建 E2 訊息
    msg = {
        "msg_type": msg_type,
        "src": "malicious_xapp",  # 標記為惡意 xApp
        "dst": "ric",
        "payload": payload,
        "timestamp": time.time(),
    }
    # 發送訊息
    sock.sendall(json.dumps(msg).encode())
    # 接收回應
    raw = sock.recv(4096)
    return json.loads(raw)


def is_blocked(resp: dict) -> bool:
    """
    檢查訊息是否被攔截器阻止

    Args:
        resp (dict): 攔截器的回應

    Returns:
        bool: True 表示訊息被阻止，False 表示訊息被允許
    """
    return resp.get("msg_type") == "Blocked"


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
            return s
        except OSError:
            logging.warning(f"Interceptor not ready, retry {attempt}/{retries} ...")
            time.sleep(delay)
    raise RuntimeError(f"Could not connect to {host}:{port} after {retries} retries")


# ── DoS 攻擊 — 跳過 Setup 直接大量送 RICindication ────────────────────────
def attack_dos():
    """
    DoS 攻擊

    攻擊者跳過 E2 Setup，直接向 RIC 發送大量 Indication 訊息。
    這違反了 FSM 規則（不能在 IDLE 狀態接收 Indication）。
    防禦層應該識別並阻止這些異常訊息。
    """
    logging.info("[ATTACK] DoS: flooding RICindication without E2 setup")
    blocked_count = 0

    with connect_with_retry(INTERCEPTOR_HOST, INTERCEPTOR_PORT) as s:
        for i in range(50):
            try:
                # 發送 50 條 Indication 訊息，不經過 Setup
                resp = send_recv(s, "RICindication", {"seq": i})
                blocked = is_blocked(resp)
                if blocked:
                    blocked_count += 1
                logging.info(f"  [{i:02d}] blocked={blocked} resp={resp.get('msg_type')}")
            except Exception as e:
                logging.error(f"  [{i:02d}] error: {e}")
                break
            time.sleep(0.02)  # 時間間隔以避免過快轟炸

    logging.info(f"[ATTACK] DoS done — {blocked_count}/50 blocked")




if __name__ == "__main__":
    attack_dos()      

