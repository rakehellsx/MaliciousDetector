# 恶意代码辅助检测系统

> 基于 Qt5 + SQLite3 开发的桌面端恶意代码辅助检测工具，支持 GCC / MSVC / MinGW 三种编译器，兼容 Linux 与 Windows 平台。

---

## 技术栈

| 组件 | 版本 / 说明 |
|---|---|
| Qt | 5.x（qtbase5-dev） |
| 数据库 | SQLite3（Qt QSQLITE 驱动） |
| 编译器 | GCC 9+ / **MSVC 2019+** / MinGW 8.1+ |
| C++ 标准 | C++17 |
| 构建系统 | CMake 3.16+ / qmake |
| 界面布局 | Qt Designer `.ui` 文件（全部 22 个页面） |
| 样式管理 | 独立 QSS 文件（`resources/styles/`） |
| 基础信息采集 | basic.dll 动态库（接口见 `third_party/basic/basic.h`） |

---

## 目录结构

```
MalwareDetector/
├── CMakeLists.txt            # CMake 构建文件（推荐）
├── MalwareDetector.pro       # Qt qmake 构建文件
├── README.md
├── include/                  # 头文件
│   ├── pages/                # 各功能页面头文件
│   ├── BasePage.h            # 所有页面基类
│   ├── StyleManager.h        # QSS 样式加载器
│   └── IconHelper.h          # 图标统一加载工具
├── src/                      # 源文件（业务逻辑）
│   └── pages/                # 各功能页面实现
├── ui/                       # Qt Designer 界面文件（22 个 .ui 文件）
├── resources/
│   ├── icons/                # 图标资源（PNG）
│   └── styles/               # QSS 样式文件
│       ├── main.qss          # 全局主题样式
│       └── login.qss         # 登录界面样式
├── tools/                    # 数据生成工具（Python / C）
└── third_party/
    └── basic/                # 基础信息采集动态库接口定义
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
  ├── 动态行为检测（含 全局行为监测 / 进程链行为分析）
  ├── 文件关联检测
  └── 样本提取
结果管理
  ├── 检测报告（支持 HTML/PDF/DOC 导出，支持定时生成策略）
  ├── 日志审计
  └── 系统设置
```

---

## 编译方法

本项目同时支持 **CMake**（推荐）和 **qmake** 两种构建方式，兼容 GCC、MSVC、MinGW 三种编译器。

### 方式一：CMake 构建（推荐）

#### Linux / GCC

```bash
# 安装依赖
sudo apt update
sudo apt install -y cmake build-essential qtbase5-dev libqt5sql5-sqlite

# 编译
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

#### Windows / MSVC 2019+（推荐）

```bat
:: 在 Visual Studio Developer Command Prompt 中执行
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64 ^
         -DCMAKE_PREFIX_PATH=C:\Qt\5.15.x\msvc2019_64 ^
         -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

> **说明**：CMakeLists.txt 已内置 MSVC 专用编译选项，无需手动配置：
> - `/utf-8`：源文件和执行字符集均使用 UTF-8，解决中文注释 C4819 警告
> - `/MP`：并行编译（多核加速）
> - `/wd4251`：抑制 Qt DLL 接口导出警告
> - `NOMINMAX` / `WIN32_LEAN_AND_MEAN`：避免 Windows 宏冲突

#### Windows / MinGW

```bat
mkdir build && cd build
cmake .. -G "MinGW Makefiles" ^
         -DCMAKE_PREFIX_PATH=C:\Qt\5.15.x\mingw81_64 ^
         -DCMAKE_BUILD_TYPE=Release
mingw32-make -j4
```

---

### 方式二：qmake 构建

#### Linux / GCC

```bash
sudo apt install qtbase5-dev qtchooser qt5-qmake build-essential
mkdir build && cd build
qmake ..
make -j$(nproc)
```

#### Windows / MSVC

```bat
:: 在 Qt Creator 中打开 MalwareDetector.pro，选择 MSVC 工具链直接构建
:: 或在 Qt 命令行环境中执行：
qmake MalwareDetector.pro
nmake release
```

> **说明**：`.pro` 文件已内置 `msvc{}` 编译选项块，自动添加 `/utf-8 /MP /W3 /wd4819 /wd4251` 及 Windows 宏定义。

#### Windows / MinGW

```bat
qmake MalwareDetector.pro
mingw32-make -j4
```

#### Linux 交叉编译 Windows 目标（MXE + MinGW）

```bash
git clone https://github.com/mxe/mxe.git && cd mxe
make qtbase qttools MXE_TARGETS=x86_64-w64-mingw32.shared -j4
export PATH=$(pwd)/usr/bin:$PATH

cd /path/to/MalwareDetector
mkdir build-mxe && cd build-mxe
x86_64-w64-mingw32.shared-qmake-qt5 ../MalwareDetector.pro
make -j4
```

---

## 部署说明

1. 将 `resources/` 目录（含 `icons/` 和 `styles/`）放置在可执行文件同级目录。CMake 构建会自动完成此步骤（`POST_BUILD` 规则）。
2. Windows 环境下，使用 `windeployqt MalwareDetector.exe` 自动部署 Qt 依赖的 DLL。
3. 可选：将 `basic.dll` 放置在可执行文件同级目录。若不存在，系统将自动降级为从 SQLite 数据库读取数据。
4. 首次运行会自动创建 `data/malware_detector.db` 数据库并初始化全部 27 张表。

---

## 样式管理

项目使用独立 QSS 文件统一管理界面样式，方便主题定制：

| 文件 | 说明 |
|---|---|
| `resources/styles/main.qss` | 全局主题（背景色、字体、按钮、表格、滚动条、Tab 等） |
| `resources/styles/login.qss` | 登录界面专属样式 |

修改 QSS 文件后**无需重新编译**，重启程序即可生效。

---

## 数据库设计

项目完全由 SQLite3 驱动，无硬编码数据。关键表包括：

- **基础信息表**：`sys_info`, `net_info`, `disk_info`, `process_info`, `port_info`, `autorun_info` 等
- **检测分析表**：`static_scan`, `dynamic_scan`, `cert_scan`, `file_assoc_scan`, `sample_extract`
- **报告与日志表**：`report_schedule`（定时报告策略）, `report_history`（历史报告）, `audit_log`
- **配置表**：`settings`, `whitelist`, `custom_rules`

> 提示：可使用 `tools/gen_data.py` 或 `tools/gen_data.c` 快速生成测试数据并导入 SQLite 数据库。

---

## 默认账号（测试数据）

| 角色 | 用户名 | 密码 |
|---|---|---|
| 系统管理员 | admin | Admin@123 |
| 安全管理员 | secadmin | Sec@123456 |
| 安全审计员 | auditor | Audit@123 |
