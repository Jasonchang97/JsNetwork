# JsNetwork

跨平台 HTTP/HTTPS 抓包分析工具，基于 Qt 5.12 + C++ + OpenSSL 构建。

## 功能特性

### 抓包引擎
- HTTP/HTTPS 被动抓包（系统代理模式）
- HTTPS MITM 中间人解密（自动生成/安装 CA 证书）
- HTTP/1.1 协议解析（支持 gzip/deflate 自动解压、chunked transfer 解码）
- HTTP/2 帧解析（HEADERS/DATA/SETTINGS/PING/GOAWAY 等）
- WebSocket 帧拦截与消息解析（Text/Binary/Ping/Pong/Close）
- 全文搜索与多维度过滤（域名、路径、方法、状态码）

### UI 功能
- 流量列表：实时滚动、颜色编码（2xx/3xx/4xx/5xx）、按列排序、万级请求性能优化
- 请求/响应详情：Headers 折叠展示、Body 自动解析
- Body 预览：JSON 格式化高亮、HTML 源码、图片预览、Hex dump
- 时间线瀑布图：DNS / TCP / TLS / TTFB / Download 各阶段耗时可视化
- 深色/浅色主题切换（QSettings 持久化）
- 中英文界面切换（QSettings 持久化）
- 工具栏：一键清空、HTTPS 解密开关、HAR 导出、主题切换、语言切换

### Mock 调试
- Mock 规则引擎：按 URL/域名/通配符/正则匹配
- Map Local：将请求映射到本地文件
- Auto Responder：预设响应自动返回（自定义状态码、Headers、Body）
- 断点调试：请求/响应断点暂停、修改后放行
- Composer：手动构造 HTTP 请求并发送（支持 GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS）

### 数据持久化与导出
- SQLite 请求历史存储（自动创建数据库，分页加载，全文搜索）
- HAR 1.2 格式导出（完整请求/响应/Headers/Body/Timings）

### 平台适配
- macOS：`security add-trusted-cert` 证书安装、`networksetup` 系统代理
- Windows：`certutil` 证书安装、注册表系统代理设置
- 双平台编译支持（CMake）
- macOS .app Bundle 打包 + CPack DMG 打包

## 构建

### 依赖
- Qt 5.12+（Core, Gui, Widgets, Network, Sql）
- OpenSSL 1.1+
- zlib（系统自带）
- CMake 3.14+
- Google Test 1.14+（可选，用于单元测试）

### macOS 编译

```bash
cd /path/to/JsNetwork

# 编译主程序 + 测试
cmake -B build -DBUILD_TESTS=ON
cmake --build build -j$(sysctl -n hw.ncpu)

# 运行测试
cd build && ./jsnetwork_tests

# 仅编译主程序（跳过测试）
cmake -B build -DBUILD_TESTS=OFF
cmake --build build
```

### Windows 编译

```powershell
# 前置条件：
# - Visual Studio 2019 或更高版本（需要 MSVC C++ 编译器）
# - CMake 3.14+
# - Qt5 和 OpenSSL（位于 D:\master\debug\xwares\3rd\ 目录下）

# 编译主程序 + 测试
cd JsNetwork
cmake -B build -G "Visual Studio 16 2019" -A Win32
cmake --build build --config Release

# 编译产物位于 build\Release\ 目录
# 生成的文件包括：
# - JsNetwork.exe        主程序
# - Qt5CoreKso.dll 等    Qt 运行时库
# - platforms\qwindows.dll  Qt 平台插件
# - jsnetwork_tests.exe  测试程序
```

### Windows 打包

**方式一：Inno Setup 安装包**
```powershell
# 安装 Inno Setup 6 后，打开 installer.iss 文件编译
# 或使用命令行：
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss
# 生成 dist\JsNetwork-v0.1.0-win32-setup.exe
```

**方式二：便携版 ZIP**
```powershell
# 运行打包脚本
package.bat
# 生成 dist\JsNetwork-v0.1.0-win32.zip
```

## 使用

```bash
# 启动（.app Bundle）
open build/JsNetwork.app

# 或直接运行
./build/JsNetwork.app/Contents/MacOS/JsNetwork

# 测试抓包（另开终端）
curl -x http://localhost:9527 http://httpbin.org/get
curl -x http://localhost:9527 https://httpbin.org/get
```

启动后：
1. 程序自动监听 `localhost:9527`
2. 自动初始化 CA 证书并尝试安装到系统信任库（需管理员权限）
3. 工具栏点击 "HTTPS Decrypt" 开关 MITM 解密
4. 设置系统代理或浏览器代理为 `127.0.0.1:9527`

### 证书管理

CA 证书在首次启动时自动生成并尝试安装到系统信任库：
- **macOS**：使用 `security add-trusted-cert` 安装到 System keychain
- **Windows**：使用 `certutil -addstore Root` 安装到受信任的根证书

如果自动安装失败，程序会输出证书路径，可手动安装：
```bash
# macOS 手动安装
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \
  ~/Library/Application\ Support/JsNetwork/certificates/ca.pem
```

### 语言切换

工具栏点击 "语言" / "Language" 按钮切换中英文界面，设置自动保存。

## 项目结构

```
JsNetwork/
├── CMakeLists.txt
├── README.md
├── docs/PRD.md                    # 产品需求文档
├── src/
│   ├── main.cpp
│   ├── app/
│   │   ├── application.{h,cpp}    # 应用生命周期、组件装配
│   │   ├── translator.{h,cpp}     # 中英文翻译管理
│   ├── core/
│   │   ├── proxy_server.{h,cpp}   # HTTP/HTTPS 代理服务器
│   │   ├── http_parser.{h,cpp}    # HTTP/1.1 协议解析
│   │   ├── http2_parser.{h,cpp}   # HTTP/2 帧解析 + HPACK
│   │   ├── websocket_parser.{h,cpp} # WebSocket 帧解析
│   │   ├── cert_manager.{h,cpp}   # CA 证书生成 + 域名证书签发
│   │   ├── mitm_engine.{h,cpp}    # MITM TLS 双向拦截引擎
│   │   ├── mock_engine.{h,cpp}    # Mock 规则引擎
│   │   ├── breakpoint_engine.{h,cpp} # 断点引擎
│   │   ├── traffic_storage.{h,cpp} # SQLite 持久化存储
│   │   ├── har_exporter.{h,cpp}   # HAR 1.2 格式导出
│   ├── model/
│   │   ├── request_item.{h,cpp}   # 请求/响应数据模型
│   ├── ui/
│   │   ├── mainwindow.{h,cpp}     # 主窗口 + 侧栏 + 工具栏
│   │   ├── trafficlistwidget.{h,cpp} # 流量列表（表格+过滤）
│   │   ├── detailpanel.{h,cpp}    # 详情面板（Tab 切换）
│   │   ├── bodypreview.{h,cpp}    # Body 预览（JSON/HTML/图片/Hex）
│   │   ├── timelinewidget.{h,cpp} # 时间线瀑布图
│   │   ├── mockpanel.{h,cpp}      # Mock 规则管理面板
│   │   ├── composerwidget.{h,cpp} # HTTP 请求构造器
│   │   ├── theme.{h,cpp}          # 深色/浅色主题切换
│   ├── platform/
│   │   ├── proxy_config.{h,cpp}   # 系统代理设置（macOS/Windows）
│   │   ├── cert_installer.{h,cpp} # 证书安装/卸载（macOS/Windows）
├── tests/
│   ├── test_main.cpp              # gtest 入口
│   ├── test_http_parser.cpp       # HTTP 解析器测试（7 cases）
│   ├── test_http2_parser.cpp      # HTTP/2 解析器测试（6 cases）
│   ├── test_websocket_parser.cpp  # WebSocket 解析器测试（9 cases）
│   └── test_mock_engine.cpp       # Mock 引擎测试（12 cases）
├── resources/
│   ├── Info.plist.in              # macOS Bundle 配置
│   ├── launcher.sh.in             # macOS 启动脚本模板
│   └── icons/                     # 应用图标
├── build/
│   ├── JsNetwork.app              # macOS 应用包
│   └── jsnetwork_tests            # 测试程序
```

## 架构

```
Client ──HTTP/HTTPS──> [JsNetwork Proxy :9527] ──HTTP/HTTPS──> Server
                              │
                    ┌─────────┴─────────┐
                    │  MITM Engine      │
                    │  (TLS 双向握手)    │
                    │  Memory BIOs      │
                    └─────────┬─────────┘
                              │
                    ┌─────────┴─────────┐
                    │  CertManager      │
                    │  (CA + 域名证书)   │
                    │  (RSA 2048 + SAN) │
                    └───────────────────┘
```

### MITM 工作流程

```
1. 浏览器 → CONNECT host:443 → JsNetwork Proxy
2. Proxy 回复 200 Connection Established
3. ServerHandshakeThread: 与真实服务器建立 TLS 连接（ALPN: http/1.1）
4. CertGenThread: 为该域名动态生成伪造证书（CA 签发，RSA 2048）
5. Memory BIO: 与浏览器完成 TLS 握手（服务端证书）
6. 双向解密转发：浏览器 ↔ Proxy（明文） ↔ 服务器（TLS）
```

## 测试

```bash
cd build && ./jsnetwork_tests
```

```
[==========] Running 34 tests from 4 test suites.
[  PASSED  ] 34 tests.
```

| 测试套件 | 用例数 | 覆盖范围 |
|---------|--------|---------|
| HttpParserTest | 7 | GET/POST 请求、200/404 响应、不完整/畸形数据、多 Headers |
| Http2ParserTest | 6 | SETTINGS/DATA/PING 帧、不完整帧、帧类型名、多帧解析 |
| WebSocketParserTest | 9 | 明文/掩码帧、Close/Ping/Pong、16 位长度、消息组装 |
| MockEngineTest | 12 | CRUD 规则、Contains/Exact/Wildcard/Regex 匹配、禁用规则、AutoResponder 应用 |

## 打包

```bash
# macOS DMG
cd build
cpack -G DragNDrop

# 生成 JsNetwork-0.1.0-Darwin.dmg
```

## 开发阶段

| 阶段 | 内容 | 状态 |
|------|------|------|
| Phase 1 | 基础框架：Qt 项目 + HTTP 代理 + 流量列表 | Done |
| Phase 2 | HTTPS MITM：CA 证书 + TLS 拦截 + 平台适配 | Done |
| Phase 3 | 协议增强：HTTP/2 + WebSocket + Body 预览 + 时间线 | Done |
| Phase 4 | Mock 调试 + Composer + gtest 单元测试 | Done |
| Phase 5 | 打磨发布：主题 + i18n + SQLite + HAR + 打包 | Done |

## License

MIT
