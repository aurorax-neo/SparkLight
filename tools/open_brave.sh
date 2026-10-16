#!/usr/bin/env bash
# 启动本地 Brave 浏览器用于人工登录抖音与复制 Cookie
# 说明: SparkLight 系统纯 Rust 原生运行，零浏览器驱动依赖，仅用此辅助人工调试。

if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "用法: ./tools/open_brave.sh [URL]"
    echo "默认以系统配置启动 /Applications/Brave Browser.app 打开 https://www.douyin.com"
    exit 0
fi

BRAVE_APP="/Applications/Brave Browser.app"
TARGET_URL="${1:-https://www.douyin.com}"

if [ ! -d "$BRAVE_APP" ]; then
    echo "错误: 未在系统中找到 Brave 浏览器: $BRAVE_APP"
    exit 1
fi

echo "正在以系统默认配置启动 Brave 浏览器打开: $TARGET_URL"
open -a "$BRAVE_APP" "$TARGET_URL"
