# FSM_Interceptor/FSM_Interceptor.py
"""
狀態機攔截器模組
基於有限狀態機(FSM)實現 E2 訊息的異常偵測和防禦
"""

from transitions import Machine  # 狀態機庫
from Metrics import MetricsCollector
import socket, json, logging, time, threading

# 配置日誌：記錄攔截器的所有操作
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Interceptor] %(levelname)s %(message)s"
)


class E2SessionFSM:
    """
    E2 會話狀態機類

    定義合法 E2 會話的狀態轉換規則。任何不符合此狀態機的訊息序列都被認為是異常。

    合法狀態流轉：
        IDLE → SETUP → ACTIVE → IDLE

    狀態說明：
        - IDLE: 初始狀態，等待 E2 Setup 請求
        - SETUP: 已接收 Setup 請求，等待 Subscription 請求
        - ACTIVE: 已訂閱，可以接收 Indication 和 Control 訊息
        - ERROR: 檢測到違規，該會話被標記為異常
    """
    states = ['IDLE', 'SETUP', 'ACTIVE', 'ERROR']

    def __init__(self, session_id):
        self.session_id = session_id
        self.violation_count = 0  # 追蹤此會話的違規次數
        # 使用 transitions 庫建立狀態機
        self.machine = Machine(
            model=self,
            states=E2SessionFSM.states,
            initial='IDLE',  # 初始狀態為 IDLE
            transitions=[
                # 從 IDLE 收到 Setup 請求 → 轉為 SETUP
                {'trigger': 'recv_setup_req',  'source': 'IDLE',   'dest': 'SETUP'},
                # 從 SETUP 收到 Subscription 請求 → 轉為 ACTIVE
                {'trigger': 'recv_sub_req',    'source': 'SETUP',  'dest': 'ACTIVE'},
                # 在 ACTIVE 狀態接收 Indication 訊息 → 保持 ACTIVE
                {'trigger': 'recv_indication', 'source': 'ACTIVE', 'dest': 'ACTIVE'},
                # 在 ACTIVE 狀態接收 Control 訊息 → 保持 ACTIVE
                {'trigger': 'recv_control',    'source': 'ACTIVE', 'dest': 'ACTIVE'},
                # Reset 訊息可以在任何狀態接收 → 轉為 IDLE
                {'trigger': 'recv_reset',      'source': '*',      'dest': 'IDLE'},
                # 異常標記觸發 → 轉為 ERROR
                {'trigger': 'flag_error',      'source': '*',      'dest': 'ERROR'},
            ]
        )

    # 訊息類型到狀態機觸發器的映射
    MSG_TRIGGER_MAP = {
        "E2SetupRequest":          "recv_setup_req",     # E2 設置請求
        "RICsubscriptionRequest":  "recv_sub_req",       # RIC 訂閱請求
        "RICindication":           "recv_indication",    # RIC 指標通知
        "RICcontrolRequest":       "recv_control",       # RIC 控制請求
        "ResetRequest":            "recv_reset",         # 重置請求
    }

    def validate(self, msg_type: str) -> bool:
        """
        驗證訊息是否符合 FSM 規則

        Args:
            msg_type (str): 訊息類型

        Returns:
            bool: True 表示訊息合法，False 表示訊息違反狀態機規則
        """
        # 取得訊息對應的狀態機觸發器
        trigger = self.MSG_TRIGGER_MAP.get(msg_type)
        if trigger is None:
            # 未知的訊息類型 → 違規
            self.violation_count += 1
            return False
        try:
            # 嘗試觸發狀態轉換
            getattr(self, trigger)()
            return True
        except Exception:
            # 狀態轉換失敗（如從 IDLE 狀態接收 Indication）→ 違規
            self.violation_count += 1
            return False


class FSMInterceptor:
    """
    FSM 攔截器核心類

    攔截器位於 xApp 和 RIC 之間，充當代理角色：
    1. 攔截來自 xApp 的訊息
    2. 使用 FSM 驗證訊息是否合法
    3. 允許合法訊息通過並轉發給 RIC，將 RIC 的回應代理回 xApp
    4. 阻止違規訊息並返回 Blocked 回應

    性能優化：
    - 被攔截時的回應被預先編碼為常數，避免每次重新建立 bytes 物件
    """
    # 被攔截時回傳的固定回應，避免每次重新建立 bytes 物件
    BLOCKED_RESP = json.dumps({
        "msg_type": "Blocked",
        "payload": {"reason": "fsm_violation"}
    }).encode()

    def __init__(self, listen_port=36422, ric_host="ric", ric_port=36421):
        """
        初始化攔截器

        Args:
            listen_port (int): 攔截器監聽的本地端口（接收 xApp 連接）
            ric_host (str): RIC 節點的主機名
            ric_port (int): RIC 節點的端口
        """
        self.listen_port = listen_port
        self.ric_host = ric_host
        self.ric_port = ric_port
        self.sessions: dict[str, E2SessionFSM] = {}  # 存儲每個會話的 FSM 實例
        self.sessions_lock = threading.Lock()  # 保護共享會話字典的鎖
        self.stats = {"allowed": 0, "blocked": 0}  # 統計允許和阻止的訊息數
        self.metrics = MetricsCollector()  # 收集性能指標

    def _get_or_create_session(self, session_id: str) -> E2SessionFSM:
        """
        取得或建立指定 session_id 的 FSM 實例

        Args:
            session_id (str): 會話標識符（通常為 "IP:PORT"）

        Returns:
            E2SessionFSM: 該會話的狀態機實例
        """
        with self.sessions_lock:
            if session_id not in self.sessions:
                self.sessions[session_id] = E2SessionFSM(session_id)
            return self.sessions[session_id]

    def handle_message(self, raw: bytes, session_id: str) -> tuple[bool, str]:
        """
        處理和驗證訊息

        Args:
            raw (bytes): 原始訊息位元組
            session_id (str): 會話標識符

        Returns:
            tuple[bool, str]: (是否允許, 訊息類型)
                - 第一個元素：True 表示訊息合法，False 表示違反 FSM 規則
                - 第二個元素：訊息類型字符串
        """
        try:
            # 解析 JSON 格式的訊息
            msg = json.loads(raw)
            msg_type = msg.get("msg_type", "Unknown")
        except json.JSONDecodeError:
            # JSON 解析失敗 → 阻止該訊息
            logging.warning(f"[BLOCK] session={session_id} malformed JSON")
            self.stats["blocked"] += 1
            return False, "MalformedJSON"

        # 取得該會話的 FSM 實例並驗證訊息
        fsm = self._get_or_create_session(session_id)
        allowed = fsm.validate(msg_type)
        status = "ALLOW" if allowed else "BLOCK"
        # 記錄驗證結果
        logging.info(
            f"[{status}] session={session_id} "
            f"type={msg_type} state={fsm.state} violations={fsm.violation_count}"
        )
        self.stats["allowed" if allowed else "blocked"] += 1
        return allowed, msg_type

    def start(self):
        """
        啟動攔截器主迴圈

        攔截器監聽指定端口，接收 xApp 連接，為每條連接創建獨立執行緒處理。
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", self.listen_port))
            srv.listen(10)  # 最多同時等待 10 個連接
            logging.info(f"FSM Interceptor listening on :{self.listen_port}")
            while True:
                # 接受 xApp 連接
                conn, addr = srv.accept()
                session_id = f"{addr[0]}:{addr[1]}"  # 基於 IP:PORT 生成會話 ID
                # 每條連線獨立執行緒，消除阻塞等待
                t = threading.Thread(
                    target=self._handle_conn,
                    args=(conn, session_id),
                    daemon=True
                )
                t.start()

    def _handle_conn(self, conn: socket.socket, session_id: str):
        """
        處理單個連接的訊息循環

        Args:
            conn (socket.socket): 與 xApp 的連接 socket
            session_id (str): 會話標識符
        """
        logging.info(f"New session: {session_id}")

        # 為此 session 建立持久性 RIC 連線（取代每條訊息重新 connect）
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
                    # 從 xApp 接收訊息
                    data = conn.recv(65535)
                    if not data:
                        break  # xApp 關閉連接

                    # 驗證訊息並記錄延遲
                    t0 = time.time()
                    allowed, msg_type = self.handle_message(data, session_id)
                    latency_ms = (time.time() - t0) * 1000
                    self.metrics.record(session_id, msg_type, allowed, latency_ms)

                    if allowed:
                        # 訊息合法：轉發給 RIC 並將真實回應代理回 xApp
                        ric_sock.sendall(data)
                        ric_resp = ric_sock.recv(65535)
                        conn.sendall(ric_resp)
                    else:
                        # 訊息違規：回傳 Blocked 回應
                        conn.sendall(self.BLOCKED_RESP)

                except (ConnectionResetError, BrokenPipeError):
                    # 連接被重置 → 結束此會話
                    break
                except Exception as e:
                    logging.error(f"Error in session {session_id}: {e}")
                    break

        logging.info(f"Session ended: {session_id}")
        self.metrics.report()


if __name__ == "__main__":
    # 啟動攔截器
    interceptor = FSMInterceptor()
    interceptor.start()
