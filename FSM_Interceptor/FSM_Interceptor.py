# FSM_Interceptor/FSM_Interceptor.py
"""
狀態機攔截器模組
基於有限狀態機 (FSM) 實現 E2 訊息的異常偵測和防禦

防禦層級：
  1. Rate Limiting — 高頻率訊息（DoS 洪水）檢測
  2. JSON Validation — 畸形封包過濾
  3. FSM State Check — 狀態機違規（亂序/未授權訊息）偵測
"""

from transitions import Machine
from Metrics import MetricsCollector
from collections import defaultdict
import socket, json, logging, time, threading

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Interceptor] %(levelname)s %(message)s"
)


# ── 速率限制器 ────────────────────────────────────────────────────────────────
class RateLimiter:
    """
    滑動視窗速率限制器

    每個 session 在 1 秒內最多允許 MAX_RATE 條訊息。
    超過閾值的訊息將在 FSM 驗證之前即被攔截，
    防禦高頻率 DoS 洪水攻擊。
    """
    MAX_RATE = 20  # 每秒最大允許訊息數（正常 xApp 約 2/s，DoS 約 50/s）

    def __init__(self):
        self._window: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, session_id: str) -> bool:
        """
        檢查 session 的當前速率是否未超過閾值。

        Returns:
            True  → 速率正常，允許繼續
            False → 超過速率上限，應阻止
        """
        now = time.time()
        with self._lock:
            ts = self._window[session_id]
            # 移除 1 秒滑動視窗外的舊時間戳
            self._window[session_id] = [t for t in ts if now - t < 1.0]
            self._window[session_id].append(now)
            return len(self._window[session_id]) <= self.MAX_RATE

    def cleanup(self, session_id: str):
        """Session 結束時清理資源"""
        with self._lock:
            self._window.pop(session_id, None)


# ── E2 會話狀態機 ─────────────────────────────────────────────────────────────
class E2SessionFSM:
    """
    E2 會話狀態機

    合法狀態流轉：IDLE → SETUP → ACTIVE → IDLE

    任何不符合此狀態機的訊息序列（包含亂序、重複 Setup、
    未訂閱就發 Indication 等）均視為異常並加以阻止。
    """
    states = ['IDLE', 'SETUP', 'ACTIVE', 'ERROR']

    # `transitions` 庫在 __init__ 時動態注入此屬性
    state: str = "IDLE"

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.violation_count = 0
        self.machine = Machine(
            model=self,
            states=E2SessionFSM.states,
            initial='IDLE',
            transitions=[
                {'trigger': 'recv_setup_req',  'source': 'IDLE',   'dest': 'SETUP'},
                {'trigger': 'recv_sub_req',    'source': 'SETUP',  'dest': 'ACTIVE'},
                {'trigger': 'recv_indication', 'source': 'ACTIVE', 'dest': 'ACTIVE'},
                {'trigger': 'recv_control',    'source': 'ACTIVE', 'dest': 'ACTIVE'},
                {'trigger': 'recv_reset',      'source': '*',      'dest': 'IDLE'},
                {'trigger': 'flag_error',      'source': '*',      'dest': 'ERROR'},
            ]
        )

    MSG_TRIGGER_MAP = {
        "E2SetupRequest":         "recv_setup_req",
        "RICsubscriptionRequest": "recv_sub_req",
        "RICindication":          "recv_indication",
        "RICcontrolRequest":      "recv_control",
        "ResetRequest":           "recv_reset",
    }

    def validate(self, msg_type: str) -> bool:
        """
        嘗試觸發 FSM 狀態轉換。

        Returns:
            True  → 轉換合法，訊息被接受
            False → 轉換非法（或未知訊息類型），視為違規
        """
        trigger = self.MSG_TRIGGER_MAP.get(msg_type if isinstance(msg_type, str) else "")
        if trigger is None:
            self.violation_count += 1
            return False
        try:
            getattr(self, trigger)()
            return True
        except Exception:
            self.violation_count += 1
            return False


# ── FSM 攔截器主體 ────────────────────────────────────────────────────────────
class FSMInterceptor:
    """
    FSM 攔截器

    架構：xApp → [Interceptor] → RIC

    攔截器作為透明代理，對每條 E2 訊息依序執行：
      1. 速率限制檢查（RateLimiter）
      2. JSON 格式驗證
      3. FSM 狀態合法性驗證

    合法訊息轉發至 RIC 並將真實回應代理回 xApp；
    違規訊息直接回傳 Blocked 回應，不觸達 RIC。
    """

    # 預先編碼各類阻止原因的回應，避免每次重新序列化
    BLOCKED_RESPONSES: dict[str, bytes] = {
        "rate_limit": json.dumps({
            "msg_type": "Blocked",
            "payload": {"reason": "rate_limit_exceeded"}
        }).encode(),
        "malformed": json.dumps({
            "msg_type": "Blocked",
            "payload": {"reason": "malformed_packet"}
        }).encode(),
        "fsm_violation": json.dumps({
            "msg_type": "Blocked",
            "payload": {"reason": "fsm_violation"}
        }).encode(),
    }

    def __init__(self, listen_port=36422, ric_host="ric", ric_port=36421):
        self.listen_port = listen_port
        self.ric_host = ric_host
        self.ric_port = ric_port
        self.sessions: dict[str, E2SessionFSM] = {}
        self.sessions_lock = threading.Lock()
        self.stats = {"allowed": 0, "blocked": 0}
        self.rate_limiter = RateLimiter()
        self.metrics = MetricsCollector()

    def _get_or_create_session(self, session_id: str) -> E2SessionFSM:
        with self.sessions_lock:
            if session_id not in self.sessions:
                self.sessions[session_id] = E2SessionFSM(session_id)
            return self.sessions[session_id]

    def handle_message(self, raw: bytes, session_id: str) -> tuple[bool, str, str]:
        """
        三層防禦管道：速率限制 → JSON 驗證 → FSM 狀態檢查

        Returns:
            (allowed, msg_type, block_reason)
        """
        # ── 第一層：速率限制 ────────────────────────────────────────────
        if not self.rate_limiter.is_allowed(session_id):
            logging.warning(f"[RATE_BLOCK] session={session_id} rate exceeded")
            self.stats["blocked"] += 1
            return False, "Unknown", "rate_limit"

        # ── 第二層：JSON 格式驗證 ────────────────────────────────────────
        try:
            msg = json.loads(raw)
            msg_type = msg.get("msg_type", "Unknown")
            # msg_type 必須是字串，否則視為畸形
            if not isinstance(msg_type, str):
                raise ValueError(f"msg_type must be str, got {type(msg_type).__name__}")
        except (json.JSONDecodeError, ValueError) as e:
            logging.warning(f"[MALFORMED_BLOCK] session={session_id} reason={e}")
            self.stats["blocked"] += 1
            return False, "MalformedPacket", "malformed"

        # ── 第三層：FSM 狀態機驗證 ───────────────────────────────────────
        fsm = self._get_or_create_session(session_id)
        allowed = fsm.validate(msg_type)
        status = "ALLOW" if allowed else "FSM_BLOCK"
        logging.info(
            f"[{status}] session={session_id} "
            f"type={msg_type} state={fsm.state} violations={fsm.violation_count}"
        )
        self.stats["allowed" if allowed else "blocked"] += 1
        reason = "" if allowed else "fsm_violation"
        return allowed, msg_type, reason

    def start(self):
        """啟動攔截器，監聽 xApp 連接"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", self.listen_port))
            srv.listen(10)
            logging.info(
                f"FSM Interceptor listening on :{self.listen_port} "
                f"(rate_limit={RateLimiter.MAX_RATE}/s)"
            )
            while True:
                conn, addr = srv.accept()
                session_id = f"{addr[0]}:{addr[1]}"
                t = threading.Thread(
                    target=self._handle_conn,
                    args=(conn, session_id),
                    daemon=True
                )
                t.start()

    def _handle_conn(self, conn: socket.socket, session_id: str):
        """處理單個連接的完整生命週期"""
        logging.info(f"New session: {session_id}")

        try:
            ric_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ric_sock.connect((self.ric_host, self.ric_port))
        except OSError as e:
            logging.error(f"Cannot reach RIC for {session_id}: {e}")
            conn.close()
            return

        with conn, ric_sock:
            while True:
                try:
                    data = conn.recv(65535)
                    if not data:
                        break

                    t0 = time.time()
                    allowed, msg_type, reason = self.handle_message(data, session_id)
                    latency_ms = (time.time() - t0) * 1000
                    self.metrics.record(session_id, msg_type, allowed, latency_ms, reason)

                    if allowed:
                        ric_sock.sendall(data)
                        ric_resp = ric_sock.recv(65535)
                        conn.sendall(ric_resp)
                    else:
                        blocked_resp = self.BLOCKED_RESPONSES.get(
                            reason, self.BLOCKED_RESPONSES["fsm_violation"]
                        )
                        conn.sendall(blocked_resp)

                except (ConnectionResetError, BrokenPipeError):
                    break
                except Exception as e:
                    logging.error(f"Error in session {session_id}: {e}")
                    break

        logging.info(f"Session ended: {session_id}")
        self.rate_limiter.cleanup(session_id)
        self.metrics.report()


if __name__ == "__main__":
    interceptor = FSMInterceptor()
    interceptor.start()
