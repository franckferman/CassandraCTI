# emoji.py
from __future__ import annotations
from .models import Event
import re

DEFAULT_MAP = {
    "ransomware.live": "🏴‍☠️ 🔒",  # 🏴‍☠️ 🔒
    "red.flag.domains": "🚩",  # 🚩
    "rss:Graham Cluley": "📰",  # 📰
    "rss:Threatpost": "📰",
    "rss:Krebs on Security": "🕵",  # 🕵
    "rss:Dark Reading": "📚",  # 📚
    "rss:Microsoft Security": "Ⓜ️",
    "rss:Checkpoint Research": "🏁",  # 🏁
    "rss:Securelist": "📜",  # 📜
}

_CC_FLAGS = {
    "fr": "🇫🇷", "uk": "🇬🇧", "gb": "🇬🇧", "de": "🇩🇪",
    "it": "🇮🇹", "es": "🇪🇸", "nl": "🇳🇱", "be": "🇧🇪",
    "lu": "🇱🇺", "ch": "🇨🇭", "us": "🇺🇸", "ca": "🇨🇦"
}

_DEF = re.compile(r"\.(fr|uk|gb|de|it|es|nl|be|lu|ch|us|ca)(/|$)")


def _flag_for_url(url: str) -> str:
    try:
        m = _DEF.search(url or "")
        if not m:
            return ""
        return _CC_FLAGS.get(m.group(1), "")
    except Exception:
        return ""


def emoji_for(ev: Event, custom_map: dict[str, str] | None = None) -> str:
    m = custom_map or {}
    if ev.source in m:
        return m[ev.source]
    if ev.source in DEFAULT_MAP:
        return DEFAULT_MAP[ev.source]
    if ev.source.startswith("rss:"):
        t = (ev.title or "").lower()
        if "microsoft" in t:
            return "Ⓜ️"
        if "cisco" in t:
            return "📡"  # 📡
        if "checkpoint" in t:
            return "🏁"  # 🏁
        return "📰"      # 📰
    if ev.source == "ransomware.live":
        flg = _flag_for_url(ev.url or "")
        return ("🏴‍☠️ 🔒 " + flg).strip()
    return "📢"  # 📢
