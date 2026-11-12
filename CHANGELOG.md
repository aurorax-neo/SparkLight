# Changelog

本项目所有重要变更均记录于此文件。
格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.1.0] - 2026-11-12

### 🚀 Features
- 纯 Rust 实现抖音多账号隔离调度、App 原生二维码登录、短信验证码登录与官方原生会话导入 (`native_session_import`)
- 实现 Scheme A 全链签名体系与 P-256 Guard 票据持久化，支持单聊与群聊每日自动及手动续火花
- 接入 iTab 每日一言随机接口，支持模板变量组合、多候选随机抽取、自定义模板编辑与批量应用
- 支持目标火花状态与今日互动状态并发刷新，内置轻量 React + TailwindCSS 控制台
- 全栈与容器统一采用北京时间 (`Asia/Shanghai`, `UTC+8`)，支持全局与账号级 Bark 静默/异常告警策略

### 🐛 Bug Fixes
- 修复手动操作误触发 Bark 通知及未确认消息历史误判导致的状态覆盖问题
- 修复重复默认模板高亮与续火花目标列表宽屏布局遮挡问题

### 🧰 Maintenance
- 接入双模 Docker 构建（`Dockerfile` 与 `Dockerfile.release`）及 GitHub Actions 多架构制品与 GHCR 容器发布流水线
