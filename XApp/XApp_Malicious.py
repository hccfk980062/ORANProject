# XApp/XApp_Malicious.py
"""
惡意 xApp 模擬模組

模擬兩類攻擊場景：
> DoS 攻擊：跳過 E2 Setup 直接大量發送 RICindication（FSM 狀態機違規）
> 畸形封包注入：發送格式異常或語意錯誤的封包

此模組用於安全測試和防禦驗證，目的是測試 FSM 攔截器的偵測能力。
"""

import socket, json, time, logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [XApp-Malicious] %(message)s"
)

INTERCEPTOR_HOST = "interceptor"
INTERCEPTOR_PORT = 36422


def send_recv(sock: socket.socket, msg_type: str, payload: dict = None) -> dict:
    """發送 E2 訊息並接收回應"""
    if payload is None:
        payload = {}
    msg = {
        "msg_type": msg_type,
        "src": "malicious_xapp",
        "dst": "ric",
        "payload": payload,
        "timestamp": time.time(),
    }
    sock.sendall(json.dumps(msg).encode())
    raw = sock.recv(4096)
    return json.loads(raw)


def is_blocked(resp: dict) -> bool:
    return resp.get("msg_type") == "Blocked"


def connect_with_retry(host: str, port: int, retries: int = 10, delay: float = 2.0) -> socket.socket:
    """帶有重試的連接函數，等待攔截器啟動就緒"""
    for attempt in range(1, retries + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            return s
        except OSError:
            logging.warning(f"Interceptor not ready, retry {attempt}/{retries} ...")
            time.sleep(delay)
    raise RuntimeError(f"Could not connect to {host}:{port} after {retries} retries")


# ── DoS — 跳過 Setup 直接大量送 RICindication ─────────────────────
def attack_dos():
    """
    DoS 攻擊（FSM 狀態機違規）

    攻擊者跳過 E2 Setup，直接向 RIC 發送大量 Indication 訊息。
    此行為違反 FSM 規則（IDLE 狀態不允許 RICindication），
    FSM 攔截器應識別並阻止全部封包。
    """
    logging.info("=" * 50)
    logging.info("[ATTACK-1] DoS: flooding RICindication without E2 Setup")
    logging.info("=" * 50)
    blocked_count = 0
    total = 50

    with connect_with_retry(INTERCEPTOR_HOST, INTERCEPTOR_PORT) as s:
        for i in range(total):
            try:
                resp = send_recv(s, "RICindication", {"seq": i, "kpi_value": 99.9})
                blocked = is_blocked(resp)
                if blocked:
                    blocked_count += 1
                logging.info(
                    f"  [{i:02d}] blocked={blocked} "
                    f"reason={resp.get('payload', {}).get('reason', '-')} "
                    f"resp={resp.get('msg_type')}"
                )
            except Exception as e:
                logging.error(f"  [{i:02d}] error: {e}")
                break
            time.sleep(0.02)  # 50 msg/sec — 高頻率模擬

    logging.info(f"[ATTACK-1] DoS done — {blocked_count}/{total} blocked ({blocked_count/total:.0%})")


# ── Malformed Packet — 畸形封包注入 ────────────────────────────────
def attack_malformed():
    """
    畸形封包注入攻擊

    向攔截器發送各種格式異常或語意錯誤的封包，
    測試輸入驗證層的防禦深度。涵蓋以下場景：
    - 非 JSON 二進位資料
    - 截斷的 JSON 字串
    - 缺少必要欄位（msg_type）
    - 未知/偽造的訊息類型
    - msg_type 型別錯誤（數字而非字串）
    - 重複 E2SetupRequest（不在 IDLE 狀態）
    - 超大 Payload（資源耗盡嘗試）
    """
    logging.info("=" * 50)
    logging.info("[ATTACK-2] Malformed Packet: injecting malformed packets")
    logging.info("=" * 50)

    # 各種畸形封包案例：(說明, 原始位元組)
    cases = [
        (
            "非JSON二進位資料",
            b"MALFORMED\x00\xff\xfe\xfd\xfc",
        ),
        (
            "截斷的JSON字串",
            b'{"msg_type": "E2SetupReque',
        ),
        (
            "缺少msg_type欄位",
            json.dumps({"src": "attacker", "dst": "ric", "payload": {}}).encode(),
        ),
        (
            "未知偽造訊息類型",
            json.dumps({
                "msg_type": "FAKE_CONTROL_OVERRIDE",
                "src": "attacker",
                "dst": "ric",
                "payload": {"cmd": "shutdown"},
            }).encode(),
        ),
        (
            "msg_type為數字型別",
            json.dumps({
                "msg_type": 9999,
                "src": "attacker",
                "payload": {},
            }).encode(),
        ),
        (
            "重複E2SetupRequest(非IDLE)",
            # 先 Setup 一次使 FSM 進入 SETUP，再重複 Setup
            # 此 case 使用獨立連接（見下方邏輯）
            None,
        ),
        (
            "超大Payload(資源耗盡)",
            json.dumps({
                "msg_type": "RICindication",
                "src": "attacker",
                "dst": "ric",
                "payload": {"junk": "A" * 16384},
            }).encode(),
        ),
        (
            "空JSON物件",
            json.dumps({}).encode(),
        ),
    ]

    blocked_count = 0
    total = 0

    for name, pkt in cases:
        # 重複 Setup 需要特殊處理：先送一次 Setup 再重複
        if pkt is None:
            try:
                with connect_with_retry(INTERCEPTOR_HOST, INTERCEPTOR_PORT, retries=3, delay=0.5) as s:
                    # 第一次 Setup（合法）
                    s.sendall(json.dumps({
                        "msg_type": "E2SetupRequest",
                        "src": "attacker",
                        "dst": "ric",
                        "payload": {"gnb_id": "evil-001"},
                        "timestamp": time.time(),
                    }).encode())
                    s.recv(4096)  # 接收 Setup Response，忽略

                    # 重複 Setup（FSM 應阻止）
                    s.sendall(json.dumps({
                        "msg_type": "E2SetupRequest",
                        "src": "attacker",
                        "dst": "ric",
                        "payload": {"gnb_id": "evil-001"},
                        "timestamp": time.time(),
                    }).encode())
                    raw = s.recv(4096)
                    if raw:
                        resp = json.loads(raw)
                        blocked = is_blocked(resp)
                        if blocked:
                            blocked_count += 1
                        total += 1
                        logging.info(
                            f"  [{name:<25}] blocked={blocked} "
                            f"reason={resp.get('payload', {}).get('reason', '-')}"
                        )
            except Exception as e:
                logging.error(f"  [{name:<25}] error: {e}")
            time.sleep(0.2)
            continue

        # 一般畸形封包：每個 case 使用新連接，避免 TCP 流汙染
        try:
            with connect_with_retry(INTERCEPTOR_HOST, INTERCEPTOR_PORT, retries=3, delay=0.5) as s:
                s.sendall(pkt)
                raw = s.recv(4096)
                if raw:
                    resp = json.loads(raw)
                    blocked = is_blocked(resp)
                    if blocked:
                        blocked_count += 1
                    total += 1
                    logging.info(
                        f"  [{name:<25}] blocked={blocked} "
                        f"reason={resp.get('payload', {}).get('reason', '-')}"
                    )
                else:
                    logging.warning(f"  [{name:<25}] empty response (connection closed by interceptor)")
        except json.JSONDecodeError as e:
            logging.error(f"  [{name:<25}] response parse error: {e}")
        except Exception as e:
            logging.error(f"  [{name:<25}] error: {e}")
        time.sleep(0.2)

    logging.info(f"[ATTACK-2] Malformed done — {blocked_count}/{total} blocked ({blocked_count/max(total,1):.0%})")


if __name__ == "__main__":
    logging.info("SUS")

    attack_dos()
    time.sleep(2)
    attack_malformed()

    logging.info("Attack Ended")
