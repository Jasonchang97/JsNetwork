# JsNetwork - 跨平台抓包软件 PRD

## 1. 产品概述

**产品名称：** JsNetwork
**定位：** 基于 Qt C++ 开发的跨平台（Windows / macOS）HTTP/HTTPS 抓包分析工具
**对标产品：** Charles Proxy / Fiddler / HTTP Toolkit
**差异化：** 开源免费、现代 UI、原生性能、MITM HTTPS 解密

---

## 2. 目标用户

| 用户群体 | 核心场景 |
|---------|---------|
| 开发者/测试 | 调试 API 接口、排查网络问题、Mock 响应 |
| 安全工程师 | 流量审计、敏感数据检测、HTTPS 明文分析 |
| 普通用户 | 查看应用网络请求、隐私合规检查 |

---

## 3. 核心功能（MVP）

### 3.1 抓包引擎
- **被动抓包：** 基于系统代理自动捕获 HTTP/HTTPS 流量
- **MITM 解密：** 自动生成并安装根证书，解密 HTTPS 明文
- **协议支持：** HTTP/1.1、HTTP/2、WebSocket
- **过滤器：** 按域名、URL、方法、状态码、Content-Type 过滤
- **搜索：** 全文搜索请求/响应内容

### 3.2 流量列表视图
- 表格展示：序号、协议、方法、Host、Path、状态码、大小、耗时
- 实时滚动，支持暂停/继续捕获
- 颜色编码：2xx 绿、3xx 蓝、4xx 橙、5xx 红
- 按列排序

### 3.3 请求/响应详情
- **概览：** URL、方法、状态码、时间线
- **Headers：** 请求头/响应头，可折叠分组
- **Body：** 自动解码（JSON 格式化、HTML 预览、图片预览、Base64 解码）
- **时间线：** DNS、TCP、TLS、TTFB、下载各阶段耗时瀑布图
- **Cookies：** 解析并展示 Request/Response Cookies

### 3.4 构造请求（Composer）
- 手动构造 HTTP 请求并发送
- 支持修改 Headers、Body、Method
- 从已有请求复制并修改重放

### 3.5 Mock / 断点
- **Map Local：** 将指定请求映射到本地文件
- **Breakpoints：** 请求/响应断点，暂停修改后再放行
- **Auto Responder：** 匹配规则自动返回预设响应

### 3.6 证书管理
- 一键生成/安装/卸载根证书（需管理员权限）
- 证书状态指示器
- 支持导出证书供其他设备使用

---

## 4. 技术架构

```
┌─────────────────────────────────────────────────┐
│                  UI Layer (Qt Quick/QML)         │
│  ┌──────────┬───────────┬──────────┬──────────┐ │
│  │流量列表  │ 详情面板   │ Mock管理  │  设置    │ │
│  └──────────┴───────────┴──────────┴──────────┘ │
├─────────────────────────────────────────────────┤
│              Core Engine (C++)                   │
│  ┌──────────┬───────────┬──────────┬──────────┐ │
│  │Proxy     │MITM       │Parser    │Storage   │ │
│  │Server    │Engine     │(HTTP/WS) │(SQLite)  │ │
│  └──────────┴───────────┴──────────┴──────────┘ │
├─────────────────────────────────────────────────┤
│           Platform Layer                         │
│  ┌──────────────────┬──────────────────────────┐│
│  │ Windows (WinHTTP) │ macOS (CFNetwork/openssl)││
│  │ 系统代理设置      │ 系统代理设置              ││
│  │ 证书安装(certutil) │ 证书安装(security CLI)   ││
│  └──────────────────┴──────────────────────────┘│
└─────────────────────────────────────────────────┘
```

### 4.1 关键技术选型

| 模块 | 技术方案 | 理由 |
|------|---------|------|
| UI 框架 | Qt 6 + QML | 现代 UI、原生性能、跨平台 |
| 网络代理 | Qt QTcpServer + 自研 HTTP Parser | 轻量可控，不依赖第三方代理库 |
| TLS/SSL | OpenSSL 3.x | MITM 证书管理、TLS 握手 |
| HTTP/2 | nghttp2 | 成熟的 HTTP/2 解析库 |
| WebSocket | Qt QWebSocket | Qt 内置支持 |
| 数据存储 | SQLite (Qt SQL) | 请求历史持久化、查询 |
| JSON 解析 | Qt QJsonDocument + nlohmann/json | 性能 + 易用 |
| 构建系统 | CMake | 跨平台构建 |
| 打包 | Windows: NSIS / macOS: DMG | 标准安装包 |

### 4.2 MITM 实现方案

```
Client ──HTTPS──> [JsNetwork Proxy] ──HTTPS──> Server
                      │
                      ├── 1. 拦截 ClientHello
                      ├── 2. 为目标域名动态生成伪造证书（CA 签发）
                      ├── 3. 与 Client 完成 TLS 握手
                      ├── 4. 与 Server 建立真实 TLS 连接
                      ├── 5. 解密、记录、转发流量
                      └── 6. 支持 HTTP/2 协商降级
```

---

## 5. UI 设计规范

### 5.1 整体布局（简洁现代风格）

```
┌──────────────────────────────────────────────────────────┐
│  ◉ ● ●    JsNetwork          🔍 搜索    ⚙ 设置   ─ □ ✕  │
├────────┬─────────────────────────────────────────────────┤
│        │ ┌─────────────────────────────────────────────┐ │
│ 全部    │ │ # Method Host          Path    Status Time │ │
│ 收藏    │ │ 1 GET   api.github.com /users  200   45ms │ │
│ 历史    │ │ 2 POST  api.example.com/login 200   120ms│ │
│ Mock    │ │ 3 GET   cdn.jsdelivr.net /lib  304   12ms │ │
│ 断点    │ │ ...                                      │ │
│        │ └─────────────────────────────────────────────┘ │
│        │ ┌─────────────────────────────────────────────┐ │
│        │ │ Tabs: 概览 | 请求 | 响应 | 时间线 | Cookies  │ │
│        │ │                                            │ │
│        │ │  Headers / Body / Preview ...               │ │
│        │ │                                            │ │
│        │ └─────────────────────────────────────────────┘ │
├────────┴─────────────────────────────────────────────────┤
│ 状态栏: 已捕获 1,234 条 | 过滤: 12 条 | 代理: 运行中 ●    │
└──────────────────────────────────────────────────────────┘
```

### 5.2 设计原则
- **配色：** 深色主题为主，支持浅色切换
- **字体：** 代码区域等宽字体（JetBrains Mono / SF Mono）
- **交互：** 右键菜单丰富、支持拖拽、双击编辑
- **响应式：** 面板可拖拽调整大小、可折叠

---

## 6. 目录结构

```
JsNetwork/
├── CMakeLists.txt
├── src/
│   ├── main.cpp
│   ├── app/                    # 应用入口、配置
│   │   ├── application.h/cpp
│   │   └── settings.h/cpp
│   ├── core/                   # 核心抓包引擎
│   │   ├── proxy_server.h/cpp      # 代理服务器
│   │   ├── mitm_engine.h/cpp       # MITM 解密引擎
│   │   ├── http_parser.h/cpp       # HTTP 协议解析
│   │   ├── http2_parser.h/cpp      # HTTP/2 解析
│   │   ├── websocket_interceptor.h/cpp
│   │   ├── cert_manager.h/cpp      # 证书生成与管理
│   │   └── traffic_storage.h/cpp   # SQLite 存储
│   ├── model/                  # 数据模型
│   │   ├── request_item.h/cpp
│   │   ├── response_item.h/cpp
│   │   └── session.h/cpp
│   ├── ui/                     # QML 界面
│   │   ├── qml/
│   │   │   ├── Main.qml
│   │   │   ├── TrafficList.qml
│   │   │   ├── DetailPanel.qml
│   │   │   ├── RequestView.qml
│   │   │   ├── ResponseView.qml
│   │   │   ├── TimelineView.qml
│   │   │   ├── MockManager.qml
│   │   │   ├── Settings.qml
│   │   │   └── components/
│   │   └── theme/
│   │       ├── Theme.qml
│   │       └── Colors.qml
│   └── platform/               # 平台适配
│       ├── proxy_config.h/cpp
│       ├── cert_installer.h/cpp
│       └── platform_utils.h/cpp
├── resources/
│   ├── icons/
│   ├── fonts/
│   └── certificates/
├── tests/
│   ├── test_http_parser.cpp
│   ├── test_mitm_engine.cpp
│   └── test_proxy_server.cpp
└── third_party/
    ├── nghttp2/
    └── openssl/
```

---

## 7. 开发阶段规划

### Phase 1 - 基础框架（2-3 周）
- [ ] Qt 6 项目脚手架 + CMake 配置
- [ ] 基础 UI 框架（主窗口、侧栏、列表、详情面板）
- [ ] HTTP 代理服务器（明文 HTTP 抓包）
- [ ] 流量列表展示

### Phase 2 - HTTPS MITM（2-3 周）
- [ ] CA 证书生成与管理
- [ ] MITM TLS 拦截引擎
- [ ] HTTPS 明文解密与展示
- [ ] 系统代理自动设置/恢复
- [ ] 证书一键安装/卸载

### Phase 3 - 协议解析增强（1-2 周）
- [ ] HTTP/2 支持
- [ ] WebSocket 拦截
- [ ] JSON/HTML/图片 Body 自动解析预览
- [ ] 时间线瀑布图

### Phase 4 - Mock 与调试（1-2 周）
- [ ] Map Local（本地映射）
- [ ] Breakpoints（断点调试）
- [ ] Auto Responder（自动响应）
- [ ] Composer（请求构造器）

### Phase 5 - 打磨与发布（1-2 周）
- [ ] 深色/浅色主题
- [ ] 请求历史持久化（SQLite）
- [ ] 导出功能（HAR 格式）
- [ ] Windows 打包（NSIS）/ macOS 打包（DMG）
- [ ] 性能优化（万级请求不卡顿）

---

## 8. 验证方式

1. **单元测试：** HTTP 解析器、MITM 引擎、证书管理的 C++ 单元测试
2. **集成测试：** 启动代理 -> 用 curl 浏览器发请求 -> 验证抓包结果
3. **手动测试：**
   - 浏览器设置代理 -> 访问 HTTPS 网站 -> 查看解密后的明文
   - Mock 规则 -> 验证请求被正确拦截/替换
   - 断点 -> 暂停请求 -> 修改后放行
4. **跨平台：** Windows 10/11 + macOS 12+ 分别验证

---

## 9. 风险与对策

| 风险 | 影响 | 对策 |
|------|------|------|
| HTTP/2 复杂度高 | Phase 3 延期 | MVP 先支持 HTTP/1.1，HTTP/2 用 nghttp2 |
| macOS 证书安装需 sudo | 用户体验 | 引导用户授权，提供手动安装教程 |
| Windows Defender 误报 | 用户信任 | 代码签名证书 + 白名单申请 |
| 大流量内存占用 | 性能 | 流式处理 + SQLite 持久化 + 虚拟滚动 |
| 部分 App 绑定证书（Certificate Pinning） | MITM 失败 | 提示用户关闭 Pinning 或提供越狱方案说明 |
