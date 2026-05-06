# FSM_Interceptor/E2AP_Messages.py
"""
E2AP 訊息定義模組
定義 O-RAN E2 介面所有支持的訊息類型和資料結構
"""

from dataclasses import dataclass
from enum import Enum


class E2MessageType(Enum):
    """E2 訊息類型枚舉 - 定義 E2AP 協議中的所有訊息類型"""
    E2_SETUP_REQUEST      = "E2SetupRequest"      # xApp 請求與 RIC 建立連接
    E2_SETUP_RESPONSE     = "E2SetupResponse"     # RIC 回應建立連接請求
    SUBSCRIPTION_REQUEST  = "RICsubscriptionRequest"   # xApp 訂閱 RAN 功能
    SUBSCRIPTION_RESPONSE = "RICsubscriptionResponse"  # RIC 回應訂閱請求
    INDICATION            = "RICindication"       # RIC 發送 KPI 指標
    CONTROL_REQUEST       = "RICcontrolRequest"   # xApp 發送控制指令
    RESET                 = "ResetRequest"        # 重置連接狀態


@dataclass
class E2Message:
    """
    E2 訊息資料結構

    Attributes:
        msg_type (str): 訊息類型 (如 "E2SetupRequest")
        src (str): 訊息來源 (如 "xapp_normal" 或 "ric")
        dst (str): 訊息目的地
        payload (dict): 訊息內容，包含訊息特定的參數
        timestamp (float): 訊息產生的時間戳
    """
    msg_type: str       # 訊息類型
    src: str            # 來源節點
    dst: str            # 目的節點
    payload: dict       # 訊息負載
    timestamp: float    # 時間戳