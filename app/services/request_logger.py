"""请求日志审计 - 记录近期请求"""

import time
import asyncio
from typing import List, Dict, Deque
from collections import deque
from dataclasses import dataclass, asdict

from app.core.logger import logger

@dataclass
class RequestLog:
    id: str
    time: str
    timestamp: float
    ip: str
    model: str
    duration: float
    status: int
    key_name: str
    token_suffix: str
    error: str = ""

class RequestLogger:
    """请求日志记录器"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, max_len: int = 1000):
        if hasattr(self, '_initialized'):
            return
            
        self._logs: Deque[Dict] = deque(maxlen=max_len)
        self._lock = asyncio.Lock()
        
        self._initialized = True

    async def add_log(self, 
                     ip: str, 
                     model: str, 
                     duration: float, 
                     status: int, 
                     key_name: str, 
                     token_suffix: str = "",
                     error: str = ""):
        """添加日志"""
        try:
            now = time.time()
            # 格式化时间
            time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
            
            log = {
                "id": str(int(now * 1000)),
                "time": time_str,
                "timestamp": now,
                "ip": ip,
                "model": model,
                "duration": round(duration, 2),
                "status": status,
                "key_name": key_name,
                "token_suffix": token_suffix,
                "error": error
            }
            
            async with self._lock:
                self._logs.appendleft(log) # 最新的在前
                
        except Exception as e:
            logger.error(f"[Logger] 记录日志失败: {e}")

    async def get_logs(self, limit: int = 1000) -> List[Dict]:
        """获取日志"""
        async with self._lock:
            return list(self._logs)[:limit]
    
    async def clear_logs(self):
        """清空日志"""
        async with self._lock:
            self._logs.clear()


# 全局实例
request_logger = RequestLogger()
