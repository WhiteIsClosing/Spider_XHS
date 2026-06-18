"""已处理笔记 / 用户的跨运行去重存储。

用一个 JSON 文件记住跑过的 note_id 与 user_id，避免重启或换关键词后把
同样的笔记评论、同样的用户重新拉一遍、重新跑 LLM——在单身份单日请求配额
很紧的前提下，省下的是宝贵的请求与 LLM 调用。

去重策略：
- 用户：永久去重。用户画像短期内基本不变，处理过就一直跳过。
- 笔记：带过期。热门笔记评论区会持续来新人，默认 3 天后允许重新爬，
        以免永久跳过导致漏掉新评论。

文件格式::

    {
        "users": ["uid1", "uid2", ...],
        "notes": {"noteid1": 1718700000.0, ...}   # id -> 上次处理的时间戳
    }
"""

import json
import os
import time

from loguru import logger

DEFAULT_NOTE_TTL_DAYS = 3


class SeenStore:
    def __init__(self, path: str = None, note_ttl_days: float = DEFAULT_NOTE_TTL_DAYS):
        self.path = path
        self.note_ttl_seconds = float(note_ttl_days) * 86400.0
        self._users: set = set()
        self._notes: dict = {}      # note_id -> last processed unix ts
        self._dirty = False
        self._load()

    # ------------------------------------------------------------------ load
    def _load(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
            self._users = set(data.get("users", []) or [])
            notes = data.get("notes", {}) or {}
            self._notes = {str(k): float(v) for k, v in notes.items()}
            logger.info(
                f"[Seen] 载入去重记录：用户 {len(self._users)} 个，笔记 {len(self._notes)} 篇"
            )
        except Exception as e:
            logger.warning(f"[Seen] 去重记录载入失败（按空处理）: {e}")
            self._users = set()
            self._notes = {}

    # ----------------------------------------------------------------- users
    def user_seen(self, user_id: str) -> bool:
        """该用户是否已处理过（永久去重）。"""
        return user_id in self._users

    def mark_user(self, user_id: str) -> None:
        if user_id and user_id not in self._users:
            self._users.add(user_id)
            self._dirty = True

    # ----------------------------------------------------------------- notes
    def note_fresh(self, note_id: str) -> bool:
        """该笔记最近是否已处理过且未过期（True 表示应跳过）。"""
        ts = self._notes.get(note_id)
        if ts is None:
            return False
        return (time.time() - ts) < self.note_ttl_seconds

    def mark_note(self, note_id: str) -> None:
        if note_id:
            self._notes[note_id] = time.time()
            self._dirty = True

    # ------------------------------------------------------------------ save
    def save(self) -> None:
        if not self.path or not self._dirty:
            return
        try:
            tmp = f"{self.path}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(
                    {"users": sorted(self._users), "notes": self._notes},
                    f, ensure_ascii=False,
                )
            os.replace(tmp, self.path)
            self._dirty = False
            logger.debug(
                f"[Seen] 已保存去重记录：用户 {len(self._users)} 个，笔记 {len(self._notes)} 篇"
            )
        except Exception as e:
            logger.warning(f"[Seen] 去重记录保存失败: {e}")
