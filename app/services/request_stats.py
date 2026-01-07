"""请求统计模块 - 按小时/天统计请求数据"""

import time
from datetime import datetime
from typing import Dict, Any
from collections import defaultdict


class RequestStats:
    """请求统计管理器（单例）"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        
        # 统计数据
        self._hourly: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "success": 0, "failed": 0})
        self._daily: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "success": 0, "failed": 0})
        self._models: Dict[str, int] = defaultdict(int)
        
        # 保留策略
        self._hourly_keep = 48  # 保留48小时
        self._daily_keep = 30   # 保留30天
        
        self._initialized = True
    
    def record_request(self, model: str, success: bool) -> None:
        """记录一次请求"""
        now = datetime.now()
        hour_key = now.strftime("%Y-%m-%dT%H")
        day_key = now.strftime("%Y-%m-%d")
        
        # 小时统计
        self._hourly[hour_key]["total"] += 1
        if success:
            self._hourly[hour_key]["success"] += 1
        else:
            self._hourly[hour_key]["failed"] += 1
        
        # 天统计
        self._daily[day_key]["total"] += 1
        if success:
            self._daily[day_key]["success"] += 1
        else:
            self._daily[day_key]["failed"] += 1
        
        # 模型统计
        self._models[model] += 1
        
        # 定期清理旧数据
        self._cleanup()
    
    def _cleanup(self) -> None:
        """清理过期数据"""
        now = datetime.now()
        
        # 清理小时数据
        hour_keys = list(self._hourly.keys())
        if len(hour_keys) > self._hourly_keep:
            for key in sorted(hour_keys)[:-self._hourly_keep]:
                del self._hourly[key]
        
        # 清理天数据
        day_keys = list(self._daily.keys())
        if len(day_keys) > self._daily_keep:
            for key in sorted(day_keys)[:-self._daily_keep]:
                del self._daily[key]
    
    def get_stats(self, hours: int = 24, days: int = 7) -> Dict[str, Any]:
        """获取统计数据"""
        now = datetime.now()
        
        # 获取最近N小时数据
        hourly_data = []
        for i in range(hours - 1, -1, -1):
            from datetime import timedelta
            dt = now - timedelta(hours=i)
            key = dt.strftime("%Y-%m-%dT%H")
            data = self._hourly.get(key, {"total": 0, "success": 0, "failed": 0})
            hourly_data.append({
                "hour": dt.strftime("%H:00"),
                "date": dt.strftime("%m-%d"),
                **data
            })
        
        # 获取最近N天数据
        daily_data = []
        for i in range(days - 1, -1, -1):
            from datetime import timedelta
            dt = now - timedelta(days=i)
            key = dt.strftime("%Y-%m-%d")
            data = self._daily.get(key, {"total": 0, "success": 0, "failed": 0})
            daily_data.append({
                "date": dt.strftime("%m-%d"),
                **data
            })
        
        # 模型统计（取 Top 10）
        model_data = sorted(self._models.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # 总计
        total_requests = sum(d["total"] for d in self._hourly.values())
        total_success = sum(d["success"] for d in self._hourly.values())
        total_failed = sum(d["failed"] for d in self._hourly.values())
        
        return {
            "hourly": hourly_data,
            "daily": daily_data,
            "models": [{"model": m, "count": c} for m, c in model_data],
            "summary": {
                "total": total_requests,
                "success": total_success,
                "failed": total_failed,
                "success_rate": round(total_success / total_requests * 100, 1) if total_requests > 0 else 0
            }
        }
    
    def reset(self) -> None:
        """重置所有统计"""
        self._hourly.clear()
        self._daily.clear()
        self._models.clear()


# 全局实例
request_stats = RequestStats()
