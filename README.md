# 恶意代码辅助检测系统

> 基于 Qt5 + SQLite3 开发的桌面端恶意代码辅助检测工具。

---

## 技术栈

| 组件 | 版本 |
|---|---|
| Qt | 5.x（qtbase5-dev） |
| 数据库 | SQLite3（Qt QSQLITE 驱动） |
| 编译器 | GCC 9+ / MSVC 2019 / MinGW 8.1 |
| 标准 | C++17 |
| 构建系统 | CMake 3.16+ / qmake |
| 基础信息采集 | basic.dll 动态库（接口见 `third_party/basic/basic.h`） |

---

## 目录结构

```
MalwareDetector/
├── CMakeLists.txt            # CMake 构建文件（推荐）
├── MalwareDetector.pro       # Qt qmake 构建文件
├── README.md
├── include/                  # 头文件
├── src/                      # 源文件（业务逻辑）
├── ui/                       # Qt Designer 界面文件 (.ui)
├── resources/                # 图标等资源文件
├── tools/                    # 数据生成工具 (Python/C)
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

本项目同时支持 **CMake**（推荐）和 **qmake** 两种构建方式。

### 方式一：使用 CMake 构建（推荐）

#### Linux 原生编译

```bash
# 1. 安装依赖
sudo apt update
sudo apt install -y cmake build-essential qtbase5-dev libqt5sql5-sqlite qtwebengine5-dev

# 2. 编译项目
mkdir build-cmake && cd build-cmake
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

#### Windows 命令行编译（使用 MinGW）

```bat
mkdir build-cmake
cd build-cmake
cmake -G "MinGW Makefiles" .. -DCMAKE_BUILD_TYPE=Release
mingw32-make -j4
```

### 方式二：使用 qmake 构建

#### Linux 原生编译

```bash
sudo apt install qtbase5-dev qtchooser qt5-qmake build-essential
mkdir build && cd build
qmake ..
make -j$(nproc)
```

#### Linux 下交叉编译 Windows 目标 (MinGW + Qt5)

使用 MXE 环境：

```bash
# 1. 克隆 MXE 仓库并编译 Qt5
git clone https://github.com/mxe/mxe.git
cd mxe
make qtbase qttools MXE_TARGETS=x86_64-w64-mingw32.shared -j4
export PATH=`pwd`/usr/bin:$PATH

# 2. 交叉编译项目
cd /path/to/MalwareDetector
mkdir build-mxe && cd build-mxe
x86_64-w64-mingw32.shared-qmake-qt5 ../MalwareDetector.pro
make -j4
```

---

## 部署说明

1. 确保将 `resources/` 目录放置在可执行文件同级或相对正确的路径。
2. Windows 环境下，可使用 `windeployqt MalwareDetector.exe` 自动部署 Qt 依赖的 DLL。
3. 可选：将 `basic.dll` 放置在可执行文件同级目录。若不存在，系统将自动降级为从 SQLite 数据库读取数据。
4. 首次运行会自动创建 `data/malware_detector.db` 数据库并初始化表结构。

---

## 数据库设计

项目完全由 SQLite3 驱动，无硬编码数据。关键表包括：
- **基础信息表**：`sys_info`, `net_info`, `disk_info`, `process_info`, `port_info`, `autorun_info` 等。
- **检测分析表**：`static_scan`, `dynamic_scan`, `cert_scan`, `file_assoc_scan`, `sample_extract`。
- **报告与日志表**：`report_schedule` (定时报告策略), `report_history` (历史报告), `audit_log`。
- **配置表**：`settings`, `whitelist`, `custom_rules`。

> 提示：可以使用 `tools/gen_data.py` 或 `tools/gen_data.c` 快速生成测试数据并导入 SQLite 数据库。

---

## 默认账号（测试数据）

| 角色 | 用户名 | 密码 |
|---|---|---|
| 系统管理员 | admin | Admin@123 |
| 安全管理员 | secadmin | Sec@123456 |
| 安全审计员 | auditor | Audit@123 |
