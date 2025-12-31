#!/usr/bin/env python3
"""测试企微通知"""
import os
from dotenv import load_dotenv

load_dotenv()

print(f"WEIXIN_WEBHOOK from env: {os.getenv('WEIXIN_WEBHOOK')}")
print(f"WEIXIN_WEBHOOK repr: {repr(os.getenv('WEIXIN_WEBHOOK'))}")

from utils.notify import notify

print(f"\nnotify.weixin_webhook: {notify.weixin_webhook}")
print(f"notify.weixin_webhook repr: {repr(notify.weixin_webhook)}")

# 测试发送
try:
    notify.send_wecom("测试标题", "测试内容")
    print("\n✅ 企微通知发送成功！")
except Exception as e:
    print(f"\n❌ 企微通知发送失败：{e}")
