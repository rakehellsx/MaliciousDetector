# 恶意代码辅助检测系统

> 基于 Qt5 + SQLite3 开发的桌面端恶意代码辅助检测工具，符合国家保密局产品目录技术指标要求。

---

## 技术栈

| 组件 | 版本 |
|---|---|
| Qt | 5.x（qtbase5-dev） |
| 数据库 | SQLite3（Qt QSQLITE 驱动） |
| 编译器 | MSVC 2019 / MinGW 8.1 / GCC 9+ |
| 标准 | C++17 |
| 基础信息采集 | basic.dll 动态库（接口见 `third_party/basic/basic.h`） |

---

## 目录结构

```
MalwareDetector/
├── MalwareDetector.pro       # Qt qmake 项目文件
├── README.md
├── .gitignore
├── include/                  # 头文件
│   ├── MainWindow.h
│   ├── LoginDialog.h
│   ├── DatabaseManager.h
│   ├── BasicLibLoader.h
│   ├── IconHelper.h
│   └── pages/
│       ├── BasePage.h
│       ├── DashboardPage.h
│       ├── SystemInfoPage.h
│       ├── NetworkInfoPage.h
│       ├── DiskInfoPage.h
│       ├── ProcessInfoPage.h
│       ├── PortInfoPage.h
│       ├── AutorunPage.h
│       ├── ScheduledTaskPage.h
│       ├── DriverInfoPage.h
│       ├── SharedResourcePage.h
│       ├── BrowserPluginPage.h
│       ├── MemoryImagePage.h
│       ├── StaticScanPage.h      # 静态检测（含数字证书Tab）
│       ├── DynamicScanPage.h
│       ├── FileAssocPage.h
│       ├── SampleExtractPage.h
│       ├── ReportPage.h
│       ├── LogAuditPage.h
│       └── SystemSettingsPage.h
├── src/                      # 源文件
│   ├── main.cpp
│   ├── MainWindow.cpp
│   ├── LoginDialog.cpp
│   ├── DatabaseManager.cpp
│   ├── BasicLibLoader.cpp
│   └── pages/
│       ├── DashboardPage.cpp
│       ├── SystemInfoPage.cpp
│       ├── NetworkInfoPage.cpp
│       ├── DiskInfoPage.cpp
│       ├── ProcessInfoPage.cpp
│       ├── PortInfoPage.cpp
│       ├── AutorunPage.cpp
│       ├── ScheduledTaskPage.cpp
│       ├── DriverInfoPage.cpp
│       ├── SharedResourcePage.cpp
│       ├── BrowserPluginPage.cpp
│       ├── MemoryImagePage.cpp
│       ├── StaticScanPage.cpp
│       ├── DynamicScanPage.cpp
│       ├── FileAssocPage.cpp
│       ├── SampleExtractPage.cpp
│       ├── ReportPage.cpp
│       ├── LogAuditPage.cpp
│       └── SystemSettingsPage.cpp
├── resources/
│   └── icons/                # PNG 图标文件（51个，运行时加载）
└── third_party/
    └── basic/
        └── basic.h           # 基础信息采集动态库接口定义
```

---

## 功能模块

### 导航结构

```
系统概览
系统信息采集
  ├── 系统基本信息
  ├── 网络信息
  ├── 硬盘信息
  ├── 进程信息
  ├── 端口信息
  ├── 自启动项
  ├── 计划任务
  ├── 驱动信息
  ├── 共享资源
  ├── 浏览器插件
  └── 内存映像
检测分析
  ├── 静态检测（含 PE结构 / 字符串提取 / 规则命中 / 数字证书 / 综合结论）
  ├── 动态行为检测
  ├── 文件关联检测
  └── 样本提取
结果管理
  ├── 检测报告
  ├── 日志审计
  └── 系统设置
```

### 静态检测模块

- **左侧文件列表**：从数据库加载已检测文件，颜色标记风险等级（红=高危、橙=中危、蓝=低危、绿=安全）
- **右侧基本属性面板**：文件名、大小、类型、MD5、SHA256、扫描时间、风险等级、**病毒检测状态**（安全/威胁）、**病毒名称**
- **详情 Tab**：PE结构 | 字符串提取 | 规则命中 | 数字证书 | 综合结论
- 数字证书检测已整合为静态检测子功能

---

## 编译方法

### Windows（推荐 Qt Creator）

1. 安装 Qt 5.15.x（含 MinGW 或 MSVC 工具链）
2. 用 Qt Creator 打开 `MalwareDetector.pro`
3. 选择 Release 构建套件，点击编译

### Windows 命令行

```bat
mkdir build && cd build
qmake ..
nmake          # MSVC
mingw32-make   # MinGW
```

### Linux（原生编译）

```bash
sudo apt install qtbase5-dev qtchooser qt5-qmake build-essential
mkdir build && cd build
qmake ..
make -j4
```

### Linux（使用 MinGW + Qt5 交叉编译 Windows 目标）

在 Linux 环境下，可以使用 MXE (M cross environment) 或 Ubuntu 源内的 `mingw-w64` 与预编译的 Qt5 库进行交叉编译，直接生成 Windows 可执行文件（`.exe`）。

#### 方法一：使用 Ubuntu 官方包（适用于 Ubuntu 20.04+）

1. 安装交叉编译工具链及 Windows 版 Qt5 库：
   ```bash
   sudo apt update
   sudo apt install mingw-w64
   # 安装预编译的 Qt5 MinGW 库（部分发行版可能需要第三方 PPA）
   # 如果没有 qtbase5-dev-mingw 类似包，建议使用 MXE（方法二）
   ```

2. 交叉编译：
   ```bash
   mkdir build-mingw && cd build-mingw
   # 使用对应架构的 qmake，例如 x86_64-w64-mingw32-qmake
   x86_64-w64-mingw32-qmake ../MalwareDetector.pro
   make -j4
   ```

#### 方法二：使用 MXE 环境（推荐，依赖最全）

1. 克隆 MXE 仓库并编译 Qt5：
   ```bash
   git clone https://github.com/mxe/mxe.git
   cd mxe
   # 编译 64 位 Windows 的 Qt5 库
   make qtbase qttools MXE_TARGETS=x86_64-w64-mingw32.shared -j4
   export PATH=`pwd`/usr/bin:$PATH
   ```

2. 交叉编译项目：
   ```bash
   cd /path/to/MalwareDetector
   mkdir build-mxe && cd build-mxe
   # 调用 MXE 提供的 qmake
   x86_64-w64-mingw32.shared-qmake-qt5 ../MalwareDetector.pro
   make -j4
   ```

编译成功后，在 `build-mxe/release/` 目录下会生成 `MalwareDetector.exe`。运行前需将对应的 Qt DLL 文件（从 MXE 的 `usr/x86_64-w64-mingw32.shared/qt5/bin/` 目录拷贝）以及 `basic.dll` 放置在同级目录下。

---

## 部署说明

1. 将 `resources/icons/` 目录与可执行文件放在同一目录
2. Windows 需运行 `windeployqt MalwareDetector.exe` 部署 Qt 依赖
3. 将 `basic.dll` 放在可执行文件同级目录（可选，不存在时从数据库读取）
4. 首次运行自动创建 SQLite 数据库并写入测试数据

---

## 数据库表结构

| 表名 | 用途 |
|---|---|
| `detection_results` | 系统信息采集结果（basic.dll 各模块 JSON 输出） |
| `static_scan` | 静态检测结果（含 `virus_name` 字段） |
| `dynamic_scan` | 动态行为检测记录 |
| `cert_scan` | 数字证书检测结果（由静态检测页面读取） |
| `file_assoc_scan` | 文件关联检测结果 |
| `sample_extract` | 样本提取记录 |
| `audit_log` | 三员操作日志 |
| `settings` | 系统配置（病毒库版本、白名单等） |

> 其他程序只需按表结构写入数据，UI 刷新时自动读取展示。

---

## basic.dll 对接

`BasicLibLoader` 使用 `QLibrary` 动态加载，支持以下接口（详见 `third_party/basic/basic.h`）：

- `getSystemInfo` / `getNetworkInfo` / `getDiskInfo`
- `getProcessInfo` / `getPortInfo` / `getAutorunInfo`
- `getScheduledTaskInfo` / `getDriverInfo` / `getSharedResourceInfo`
- `getBrowserPluginInfo` / `getMemoryImageInfo`

加载成功时直接调用 DLL 接口；未加载时自动降级为从 SQLite 读取。

---

## 默认账号（测试数据）

| 角色 | 用户名 | 密码 |
|---|---|---|
| 系统管理员 | admin | Admin@123 |
| 安全管理员 | secadmin | Sec@123456 |
| 安全审计员 | auditor | Audit@123 |
