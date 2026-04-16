# 恶意代码辅助检测系统 V3.0 — Qt5 WebEngine 版

## 技术架构

本版本（msvc3 分支）采用 **Qt5 + QWebEngineView** 方式实现，将原型 `prototype_v5.html` 作为内嵌 Web 应用运行在 Chromium 内核中，通过 **QWebChannel** 实现 C++ 与 JavaScript 的双向通信。

```
┌─────────────────────────────────────────────────────────┐
│  Qt5 MainWindow (C++)                                   │
│  ┌───────────────────────────────────────────────────┐  │
│  │  QWebEngineView (Chromium 内核)                   │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │  index.html (prototype_v5 适配版)           │  │  │
│  │  │  ├── 登录页 / 主界面 / 所有功能页面         │  │  │
│  │  │  └── QWebChannel JS ↔ AppBridge (C++)       │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
│  AppBridge (C++) — 数据层 + 窗口控制                    │
└─────────────────────────────────────────────────────────┘
```

## Win7 32位兼容性

| 方案 | Qt 版本 | Chromium 版本 | Win7 32位支持 |
|------|---------|---------------|---------------|
| **推荐（发布）** | Qt 5.6.3 LTS | Chromium 49 | ✅ 完全支持 |
| 开发验证 | Qt 5.15.x | Chromium 87+ | ❌ 不支持 Win7 |

**Win7 32位编译步骤：**
1. 下载 [Qt 5.6.3 for Windows 32-bit (VS 2015)](https://download.qt.io/archive/qt/5.6/5.6.3/)
2. 安装 Visual Studio 2015（MSVC 140）
3. 使用 `MalwareDetectorWeb.pro` 或 `CMakeLists.txt` 编译

## 项目结构

```
MaliciousDetector_qt/
├── CMakeLists.txt          # CMake 构建文件（Qt5 WebEngine）
├── MalwareDetectorWeb.pro  # qmake 构建文件（兼容 Qt 5.6+）
├── web/
│   ├── index.html          # 主 Web 应用（prototype_v5 适配版）
│   └── resources.qrc       # Qt 资源文件
├── web_src/
│   ├── include/
│   │   ├── MainWindow.h    # 主窗口（QWebEngineView 嵌入）
│   │   └── AppBridge.h     # C++/JS 通信桥接类
│   └── src/
│       ├── main.cpp        # 程序入口
│       ├── MainWindow.cpp  # 主窗口实现
│       └── AppBridge.cpp   # Bridge 实现（演示数据 + 窗口控制）
└── prototype_v5.html       # 原始原型文件（参考）
```

## C++ Bridge 接口

`AppBridge` 类通过 `QWebChannel` 暴露给 JavaScript，JS 端通过 `window.bridge` 访问：

### 数据查询接口（返回 JSON 字符串）

| 方法 | 说明 |
|------|------|
| `getDashboardData()` | 系统概览统计数据 |
| `getSysInfoData()` | 系统信息（OS/CPU/内存等） |
| `getNetInfoData()` | 网络连接列表 |
| `getDiskInfoData()` | 硬盘分区信息 |
| `getProcInfoData()` | 进程列表 |
| `getPortInfoData()` | 端口监听列表 |
| `getAutorunData()` | 自启动项（注册表/启动文件夹/右键菜单/调试器） |
| `getScheduleData()` | 计划任务列表 |
| `getDriverData()` | 驱动信息列表 |
| `getShareData()` | 共享资源列表 |
| `getBrowserPluginData()` | 浏览器插件列表 |
| `getMemoryData()` | 内存映像（内核模块+进程内存） |
| `getLogData()` | 日志审计数据 |
| `getUserData()` | 用户管理数据 |
| `getVulnData()` | 漏洞监测数据（5条CVE） |
| `getProcDetail(name)` | 进程详情（模块/线程/句柄） |

### 操作接口

| 方法 | 说明 |
|------|------|
| `login(role, username, password)` | 用户登录 |
| `logout()` | 用户登出 |
| `minimizeWindow()` | 最小化窗口 |
| `maximizeWindow()` | 最大化窗口 |
| `toggleMaximize()` | 切换最大化/正常 |
| `closeWindow()` | 关闭窗口 |

### 信号（C++ → JS）

| 信号 | 说明 |
|------|------|
| `loginResult(bool, QString)` | 登录结果回调 |
| `dataUpdated(QString, QString)` | 数据更新推送 |
| `notifyMessage(QString, QString)` | 通知消息推送 |

## Linux 编译

```bash
# 安装依赖
sudo apt-get install -y qtwebengine5-dev libqt5webchannel5-dev

# 编译
mkdir build_web && cd build_web
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# 运行
./MalwareDetectorWeb
```

## Windows 编译（Win7 32位）

```bat
# 使用 Qt 5.6.3 + MSVC2015 x86
set QTDIR=C:\Qt\5.6.3\msvc2015
set PATH=%QTDIR%\bin;%PATH%

mkdir build && cd build
cmake -G "Visual Studio 14 2015" -DCMAKE_BUILD_TYPE=Release ..
msbuild MalwareDetectorWeb.sln /p:Configuration=Release /p:Platform=Win32
```
