#include "AppBridge.h"
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QFile>
#include <QDebug>
#include <QApplication>
#include <QMainWindow>
#include <QWidget>

AppBridge::AppBridge(QObject *parent)
    : QObject(parent)
    , m_loggedIn(false)
{
}

// ── 登录/登出 ──────────────────────────────────────────────────────────────

void AppBridge::login(const QString &role, const QString &username, const QString &password)
{
    Q_UNUSED(password)
    // 演示模式：任意密码均可登录
    m_currentRole = role;
    m_currentUser = username.isEmpty() ? "admin" : username;
    m_loggedIn = true;
    emit loginResult(true, "登录成功");
}

void AppBridge::logout()
{
    m_loggedIn = false;
    m_currentUser.clear();
    m_currentRole.clear();
    emit loginResult(false, "已登出");
}

// ── 窗口控制 ────────────────────────────────────────────────────────────────

void AppBridge::minimizeWindow()
{
    QWidget *w = qobject_cast<QWidget*>(parent());
    if (w) w->showMinimized();
}

void AppBridge::maximizeWindow()
{
    QWidget *w = qobject_cast<QWidget*>(parent());
    if (w) w->showMaximized();
}

void AppBridge::closeWindow()
{
    QWidget *w = qobject_cast<QWidget*>(parent());
    if (w) w->close();
}

void AppBridge::toggleMaximize()
{
    QWidget *w = qobject_cast<QWidget*>(parent());
    if (!w) return;
    if (w->isMaximized()) w->showNormal();
    else w->showMaximized();
}

// ── 工具函数 ────────────────────────────────────────────────────────────────

QString AppBridge::getAppVersion()
{
    return QApplication::applicationVersion();
}

QString AppBridge::getCurrentUser()
{
    return m_currentUser;
}

QString AppBridge::getCurrentRole()
{
    return m_currentRole;
}

void AppBridge::exportData(const QString &pageId, const QString &format)
{
    Q_UNUSED(pageId)
    Q_UNUSED(format)
    emit notifyMessage("info", "导出功能开发中...");
}

void AppBridge::openFile(const QString &path)
{
    Q_UNUSED(path)
    emit notifyMessage("info", "文件打开功能开发中...");
}

// ── 演示数据 ─────────────────────────────────────────────────────────────────

QString AppBridge::getDashboardData()
{
    QJsonObject obj;
    obj["scan_time"]      = "2025-11-20 09:41:33";
    obj["threat_count"]   = 12;
    obj["high_risk"]      = 5;
    obj["mid_risk"]       = 4;
    obj["low_risk"]       = 3;
    obj["safe_count"]     = 1847;
    obj["last_update"]    = "2025-11-20 08:00:00";
    obj["db_version"]     = "v20251120.001";
    obj["cpu_usage"]      = "23%";
    obj["mem_usage"]      = "4.2 GB / 16 GB";
    obj["os_name"]        = "Windows 7 SP1 x86";
    obj["hostname"]       = "WORKSTATION-01";

    QJsonArray threats;
    auto addThreat = [&](const QString &name, const QString &path,
                         const QString &type, const QString &level,
                         const QString &time) {
        QJsonObject t;
        t["name"] = name; t["path"] = path;
        t["type"] = type; t["level"] = level; t["time"] = time;
        threats.append(t);
    };
    addThreat("svchost32.exe",  "C:\\Windows\\Temp\\svchost32.exe",  "木马",   "高危", "09:41:00");
    addThreat("payload.exe",    "C:\\Windows\\Temp\\payload.exe",    "后门",   "高危", "09:40:55");
    addThreat("hiddrv.sys",     "C:\\Windows\\System32\\hiddrv.sys", "Rootkit","中危", "09:38:20");
    addThreat("inject.dll",     "C:\\Windows\\Temp\\inject.dll",     "注入",   "高危", "09:41:01");
    addThreat("wuauclt32.exe",  "C:\\Windows\\Temp\\wuauclt32.exe",  "蠕虫",   "高危", "09:35:10");
    obj["recent_threats"] = threats;

    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getSysInfoData()
{
    QJsonObject obj;
    obj["os"]          = "Windows 7 SP1 旗舰版 (Build 7601)";
    obj["arch"]        = "x86 (32位)";
    obj["hostname"]    = "WORKSTATION-01";
    obj["domain"]      = "CORP.LOCAL";
    obj["cpu"]         = "Intel Core i5-4590 @ 3.30GHz";
    obj["cpu_cores"]   = "4 核 4 线程";
    obj["ram"]         = "4096 MB (DDR3)";
    obj["disk"]        = "500 GB (SATA HDD)";
    obj["mac"]         = "00:1A:2B:3C:4D:5E";
    obj["ip"]          = "192.168.1.100";
    obj["gateway"]     = "192.168.1.1";
    obj["dns"]         = "8.8.8.8 / 114.114.114.114";
    obj["uptime"]      = "3天 14小时 22分钟";
    obj["install_date"]= "2024-03-15";
    obj["last_boot"]   = "2025-11-17 19:18:44";
    obj["bios"]        = "American Megatrends Inc. F.42 (2020-08-12)";
    obj["board"]       = "ASUSTeK COMPUTER INC. H81M-K";
    obj["antivirus"]   = "Windows Defender (已启用)";
    obj["firewall"]    = "Windows 防火墙 (已启用)";
    obj["uac"]         = "已启用";
    obj["patches"]     = 187;
    obj["missing_patches"] = 3;
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getNetInfoData()
{
    QJsonArray rows;
    auto addRow = [&](const QString &proto, const QString &local,
                      int lport, const QString &remote, int rport,
                      const QString &state, const QString &proc,
                      int pid, const QString &risk) {
        QJsonObject r;
        r["proto"]=proto; r["local"]=local; r["lport"]=lport;
        r["remote"]=remote; r["rport"]=rport; r["state"]=state;
        r["proc"]=proc; r["pid"]=pid; r["risk"]=risk;
        rows.append(r);
    };
    addRow("TCP","192.168.1.100",49152,"185.220.101.45",4444,"ESTABLISHED","svchost32.exe",9012,"高危");
    addRow("TCP","192.168.1.100",49200,"192.168.1.150",445,"ESTABLISHED","payload.exe",9012,"高危");
    addRow("TCP","192.168.1.100",52341,"142.250.80.100",443,"ESTABLISHED","chrome.exe",5678,"正常");
    addRow("TCP","0.0.0.0",3389,"",0,"LISTENING","svchost.exe",876,"中危");
    addRow("TCP","0.0.0.0",445,"",0,"LISTENING","System",4,"中危");
    addRow("TCP","0.0.0.0",135,"",0,"LISTENING","svchost.exe",876,"低危");
    addRow("UDP","0.0.0.0",137,"",0,"","System",4,"正常");
    addRow("UDP","0.0.0.0",138,"",0,"","System",4,"正常");
    addRow("TCP","127.0.0.1",5037,"",0,"LISTENING","adb.exe",3456,"正常");
    addRow("TCP","192.168.1.100",49300,"10.0.0.55",8080,"ESTABLISHED","wuauclt32.exe",3456,"高危");
    QJsonObject obj; obj["rows"] = rows;
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getDiskInfoData()
{
    QJsonArray rows;
    auto addRow = [&](const QString &drive, const QString &label,
                      const QString &fs, const QString &total,
                      const QString &used, const QString &free,
                      int pct, const QString &type, const QString &risk) {
        QJsonObject r;
        r["drive"]=drive; r["label"]=label; r["fs"]=fs;
        r["total"]=total; r["used"]=used; r["free"]=free;
        r["pct"]=pct; r["type"]=type; r["risk"]=risk;
        rows.append(r);
    };
    addRow("C:","系统盘","NTFS","120 GB","98 GB","22 GB",82,"SSD","高危");
    addRow("D:","数据盘","NTFS","380 GB","210 GB","170 GB",55,"HDD","正常");
    addRow("E:","备份盘","NTFS","500 GB","50 GB","450 GB",10,"HDD","正常");
    QJsonObject obj; obj["rows"] = rows;
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getProcInfoData()
{
    QJsonArray rows;
    auto addRow = [&](int pid, const QString &name, const QString &path,
                      const QString &pub, const QString &cpu,
                      const QString &mem, int thr,
                      const QString &risk, const QString &status) {
        QJsonObject r;
        r["pid"]=pid; r["name"]=name; r["path"]=path;
        r["publisher"]=pub; r["cpu"]=cpu; r["mem"]=mem;
        r["threads"]=thr; r["risk"]=risk; r["status"]=status;
        rows.append(r);
    };
    addRow(9012,"svchost32.exe","C:\\Windows\\Temp\\svchost32.exe","未知","8.6%","96 MB",6,"高危","运行中");
    addRow(9012,"payload.exe","C:\\Windows\\Temp\\payload.exe","未知","3.2%","48 MB",4,"高危","运行中");
    addRow(3456,"wuauclt32.exe","C:\\Windows\\Temp\\wuauclt32.exe","未知","2.1%","32 MB",3,"高危","运行中");
    addRow(2345,"hiddrv.sys","C:\\Windows\\System32\\hiddrv.sys","未知","0.5%","8 MB",2,"中危","运行中");
    addRow(1234,"explorer.exe","C:\\Windows\\explorer.exe","Microsoft Corporation","1.2%","45 MB",18,"正常","运行中");
    addRow(876,"svchost.exe","C:\\Windows\\System32\\svchost.exe","Microsoft Corporation","0.8%","28 MB",12,"正常","运行中");
    addRow(5678,"chrome.exe","C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","Google LLC","4.5%","320 MB",24,"正常","运行中");
    addRow(7890,"notepad.exe","C:\\Windows\\System32\\notepad.exe","Microsoft Corporation","0.1%","8 MB",3,"正常","运行中");
    addRow(4,"System","","Microsoft Corporation","0.3%","0.5 MB",100,"正常","运行中");
    addRow(0,"[System Idle Process]","","","91.0%","0 MB",4,"正常","运行中");
    QJsonObject obj; obj["rows"] = rows;
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getPortInfoData()
{
    QJsonArray rows;
    auto addRow = [&](const QString &proto, const QString &local,
                      int lport, const QString &remote, int rport,
                      const QString &state, const QString &proc,
                      int pid, const QString &risk) {
        QJsonObject r;
        r["proto"]=proto; r["local"]=local; r["lport"]=lport;
        r["remote"]=remote; r["rport"]=rport; r["state"]=state;
        r["proc"]=proc; r["pid"]=pid; r["risk"]=risk;
        rows.append(r);
    };
    addRow("TCP","192.168.1.100",49152,"185.220.101.45",4444,"ESTABLISHED","svchost32.exe",9012,"高危");
    addRow("TCP","192.168.1.100",49200,"192.168.1.150",445,"ESTABLISHED","payload.exe",9012,"高危");
    addRow("TCP","0.0.0.0",3389,"",0,"LISTENING","svchost.exe",876,"中危");
    addRow("TCP","0.0.0.0",445,"",0,"LISTENING","System",4,"中危");
    addRow("TCP","0.0.0.0",135,"",0,"LISTENING","svchost.exe",876,"低危");
    addRow("TCP","192.168.1.100",52341,"142.250.80.100",443,"ESTABLISHED","chrome.exe",5678,"正常");
    addRow("UDP","0.0.0.0",137,"",0,"","System",4,"正常");
    addRow("UDP","0.0.0.0",138,"",0,"","System",4,"正常");
    QJsonObject obj; obj["rows"] = rows;
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getAutorunData()
{
    QJsonObject obj;

    // 注册表自启动
    QJsonArray reg;
    auto addReg = [&](const QString &name, const QString &path,
                      const QString &pub, const QString &key,
                      const QString &risk) {
        QJsonObject r;
        r["name"]=name; r["path"]=path; r["publisher"]=pub;
        r["key"]=key; r["risk"]=risk;
        reg.append(r);
    };
    addReg("svchost32","C:\\Windows\\Temp\\svchost32.exe","未知",
           "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","高危");
    addReg("payload","C:\\Windows\\Temp\\payload.exe","未知",
           "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","高危");
    addReg("OneDrive","C:\\Users\\Admin\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
           "Microsoft Corporation","HKCU\\...\\Run","正常");
    addReg("SecurityHealth","C:\\Windows\\System32\\SecurityHealthSystray.exe",
           "Microsoft Corporation","HKLM\\...\\Run","正常");
    obj["registry"] = reg;

    // 启动文件夹
    QJsonArray folder;
    auto addFolder = [&](const QString &name, const QString &path,
                         const QString &pub, const QString &loc,
                         const QString &risk) {
        QJsonObject r;
        r["name"]=name; r["path"]=path; r["publisher"]=pub;
        r["location"]=loc; r["risk"]=risk;
        folder.append(r);
    };
    addFolder("wuauclt32.exe","C:\\Windows\\Temp\\wuauclt32.exe","未知",
              "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup","高危");
    addFolder("desktop.ini","C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\desktop.ini",
              "Microsoft Corporation","用户启动文件夹","正常");
    obj["startup_folder"] = folder;

    // 右键菜单
    QJsonArray menu;
    auto addMenu = [&](const QString &ext, const QString &cmd,
                       const QString &path, const QString &risk) {
        QJsonObject r;
        r["extension"]=ext; r["command"]=cmd; r["path"]=path; r["risk"]=risk;
        menu.append(r);
    };
    addMenu("*","open","C:\\Windows\\Temp\\payload.exe \"%1\"","高危");
    addMenu(".txt","open","C:\\Windows\\System32\\notepad.exe \"%1\"","正常");
    addMenu(".pdf","open","C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe \"%1\"","正常");
    obj["context_menu"] = menu;

    // 调试器劫持
    QJsonArray dbg;
    auto addDbg = [&](const QString &target, const QString &debugger,
                      const QString &path, const QString &risk) {
        QJsonObject r;
        r["target"]=target; r["debugger"]=debugger; r["path"]=path; r["risk"]=risk;
        dbg.append(r);
    };
    addDbg("svchost.exe","C:\\Windows\\Temp\\inject.dll",
           "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe","高危");
    addDbg("taskmgr.exe","C:\\Windows\\Temp\\payload.exe",
           "HKLM\\...\\Image File Execution Options\\taskmgr.exe","高危");
    obj["debugger"] = dbg;

    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getScheduleData()
{
    QJsonArray rows;
    auto addRow = [&](const QString &name, const QString &path,
                      const QString &trigger, const QString &last,
                      const QString &next, const QString &status,
                      const QString &risk) {
        QJsonObject r;
        r["name"]=name; r["path"]=path; r["trigger"]=trigger;
        r["last_run"]=last; r["next_run"]=next;
        r["status"]=status; r["risk"]=risk;
        rows.append(r);
    };
    addRow("MalwareUpdate","C:\\Windows\\Temp\\svchost32.exe /update",
           "每日 02:00","2025-11-20 02:00:01","2025-11-21 02:00:00","就绪","高危");
    addRow("PayloadSync","C:\\Windows\\Temp\\payload.exe -sync",
           "每15分钟","2025-11-20 09:30:00","2025-11-20 09:45:00","运行中","高危");
    addRow("WindowsDefenderScheduledScan","C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\...",
           "每日 03:00","2025-11-20 03:00:05","2025-11-21 03:00:00","就绪","正常");
    addRow("GoogleUpdateTaskMachineCore","C:\\Program Files\\Google\\Update\\GoogleUpdate.exe /c",
           "每日 09:00","2025-11-20 09:00:10","2025-11-21 09:00:00","就绪","正常");
    QJsonObject obj; obj["rows"] = rows;
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getDriverData()
{
    QJsonArray rows;
    auto addRow = [&](const QString &name, const QString &path,
                      const QString &pub, const QString &ver,
                      const QString &mtime, const QString &sign,
                      const QString &type, const QString &risk) {
        QJsonObject r;
        r["name"]=name; r["path"]=path; r["publisher"]=pub;
        r["version"]=ver; r["mtime"]=mtime; r["sign"]=sign;
        r["type"]=type; r["risk"]=risk;
        rows.append(r);
    };
    addRow("hiddrv.sys","C:\\Windows\\System32\\hiddrv.sys","未知","1.0.0.1",
           "2025-11-20","未签名","内核驱动","高危");
    addRow("inject.sys","C:\\Windows\\Temp\\inject.sys","未知","1.0.0.0",
           "2025-11-20","未签名","内核驱动","高危");
    addRow("ntfs.sys","C:\\Windows\\System32\\drivers\\ntfs.sys",
           "Microsoft Corporation","6.1.7601.24545","2024-01-15","已签名","文件系统驱动","正常");
    addRow("tcpip.sys","C:\\Windows\\System32\\drivers\\tcpip.sys",
           "Microsoft Corporation","6.1.7601.24545","2024-01-15","已签名","网络驱动","正常");
    addRow("ndis.sys","C:\\Windows\\System32\\drivers\\ndis.sys",
           "Microsoft Corporation","6.1.7601.24545","2024-01-15","已签名","网络驱动","正常");
    QJsonObject obj; obj["rows"] = rows;
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getShareData()
{
    QJsonArray rows;
    auto addRow = [&](const QString &name, const QString &type,
                      int users, const QString &path,
                      const QString &perm, const QString &risk) {
        QJsonObject r;
        r["name"]=name; r["type"]=type; r["current_users"]=users;
        r["path"]=path; r["permission"]=perm; r["risk"]=risk;
        rows.append(r);
    };
    addRow("ADMIN$","管理共享",0,"C:\\Windows","完全控制","中危");
    addRow("C$","默认共享",0,"C:\\","完全控制","中危");
    addRow("IPC$","IPC共享",2,"","无","低危");
    addRow("SharedDocs","普通共享",1,"C:\\Users\\Public\\Documents","读/写","正常");
    QJsonObject obj; obj["rows"] = rows;
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getBrowserPluginData()
{
    QJsonArray rows;
    auto addRow = [&](const QString &name, const QString &browser,
                      const QString &ver, const QString &path,
                      const QString &pub, const QString &status,
                      const QString &risk) {
        QJsonObject r;
        r["name"]=name; r["browser"]=browser; r["version"]=ver;
        r["path"]=path; r["publisher"]=pub;
        r["status"]=status; r["risk"]=risk;
        rows.append(r);
    };
    addRow("MalwareHelper","Chrome","1.0.0",
           "C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\abc123",
           "未知","已启用","高危");
    addRow("KeyLogger Extension","Chrome","2.1.3",
           "C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\xyz789",
           "未知","已启用","高危");
    addRow("AdBlock Plus","Chrome","3.18.0",
           "C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\cfhdojbkjhnklbpkdaibdccddilifddb",
           "Adblock Plus","已启用","正常");
    addRow("uBlock Origin","Chrome","1.54.0",
           "C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\cjpalhdlnbpafiamejdnhcphjbkeiagm",
           "Raymond Hill","已启用","正常");
    QJsonObject obj; obj["rows"] = rows;
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getMemoryData()
{
    QJsonObject obj;

    // 内核模块
    QJsonArray kernel;
    auto addKernel = [&](const QString &name, const QString &base,
                         const QString &size, const QString &path,
                         const QString &sign, const QString &risk) {
        QJsonObject r;
        r["name"]=name; r["base"]=base; r["size"]=size;
        r["path"]=path; r["sign"]=sign; r["risk"]=risk;
        kernel.append(r);
    };
    addKernel("hiddrv.sys","0xFFFF880001000000","0x8000",
              "C:\\Windows\\System32\\hiddrv.sys","未签名","高危");
    addKernel("inject.sys","0xFFFF880001100000","0x4000",
              "C:\\Windows\\Temp\\inject.sys","未签名","高危");
    addKernel("ntoskrnl.exe","0xFFFF800000000000","0x800000",
              "C:\\Windows\\System32\\ntoskrnl.exe","已签名","正常");
    addKernel("hal.dll","0xFFFF800000800000","0x80000",
              "C:\\Windows\\System32\\hal.dll","已签名","正常");
    obj["kernel_modules"] = kernel;

    // 进程内存
    QJsonArray procs;
    auto addProc = [&](const QString &name, int pid,
                       const QString &base, const QString &size,
                       const QString &perm, const QString &type,
                       const QString &risk) {
        QJsonObject r;
        r["name"]=name; r["pid"]=pid; r["base"]=base;
        r["size"]=size; r["permission"]=perm; r["type"]=type; r["risk"]=risk;
        procs.append(r);
    };
    addProc("svchost32.exe",9012,"0x00400000","0x10000","RWX","可执行","高危");
    addProc("svchost32.exe",9012,"0x10000000","0x5000","RWX","注入代码","高危");
    addProc("explorer.exe",1234,"0x00400000","0x200000","RX","可执行","正常");
    addProc("chrome.exe",5678,"0x00400000","0x500000","RX","可执行","正常");
    obj["proc_memory"] = procs;

    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getLogData()
{
    QJsonArray rows;
    auto addRow = [&](const QString &time, const QString &user,
                      const QString &role, const QString &type,
                      const QString &action, const QString &result,
                      const QString &ip) {
        QJsonObject r;
        r["time"]=time; r["user"]=user; r["role"]=role;
        r["type"]=type; r["action"]=action; r["result"]=result; r["ip"]=ip;
        rows.append(r);
    };
    addRow("2025-11-20 09:41:33","admin","管理员","系统","全盘扫描完成，发现12个威胁","成功","192.168.1.100");
    addRow("2025-11-20 09:41:00","admin","管理员","威胁","检测到高危进程 svchost32.exe","警告","192.168.1.100");
    addRow("2025-11-20 09:40:55","admin","管理员","威胁","检测到后门程序 payload.exe","警告","192.168.1.100");
    addRow("2025-11-20 09:38:20","admin","管理员","威胁","检测到 Rootkit hiddrv.sys","警告","192.168.1.100");
    addRow("2025-11-20 09:35:10","admin","管理员","威胁","检测到蠕虫 wuauclt32.exe","警告","192.168.1.100");
    addRow("2025-11-20 09:30:00","admin","管理员","登录","用户登录系统","成功","192.168.1.100");
    addRow("2025-11-20 09:00:00","system","系统","更新","病毒库更新完成 v20251120.001","成功","127.0.0.1");
    addRow("2025-11-20 08:00:00","operator","操作员","扫描","快速扫描完成，未发现威胁","成功","192.168.1.101");
    addRow("2025-11-20 07:30:00","operator","操作员","登录","用户登录系统","成功","192.168.1.101");
    addRow("2025-11-19 23:00:00","system","系统","备份","日志备份完成","成功","127.0.0.1");
    QJsonObject obj; obj["rows"] = rows;
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getUserData()
{
    QJsonArray rows;
    auto addRow = [&](const QString &username, const QString &role,
                      const QString &realname, const QString &dept,
                      const QString &last_login, const QString &status) {
        QJsonObject r;
        r["username"]=username; r["role"]=role; r["realname"]=realname;
        r["dept"]=dept; r["last_login"]=last_login; r["status"]=status;
        rows.append(r);
    };
    addRow("admin","管理员","系统管理员","信息安全部","2025-11-20 09:30:00","正常");
    addRow("operator","操作员","张三","信息安全部","2025-11-20 07:30:00","正常");
    addRow("auditor","审计员","李四","审计部","2025-11-19 16:00:00","正常");
    addRow("viewer","查看者","王五","运维部","2025-11-18 10:00:00","禁用");
    QJsonObject obj; obj["rows"] = rows;
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QString AppBridge::getVulnData()
{
    QJsonArray arr;
    auto addVuln = [&](int id, const QString &procPath, int pid,
                       const QString &tool, const QString &desc,
                       const QString &srcIp, int srcPort,
                       const QString &dstIp, int dstPort,
                       const QString &proto, const QString &level,
                       const QString &cve, const QString &cveDate,
                       const QString &cvss, const QString &affected,
                       const QString &cveDesc, const QString &advice) {
        QJsonObject o;
        o["id"]=id; o["procPath"]=procPath; o["pid"]=pid;
        o["tool"]=tool; o["desc"]=desc;
        o["srcIp"]=srcIp; o["srcPort"]=srcPort;
        o["dstIp"]=dstIp; o["dstPort"]=dstPort; o["proto"]=proto;
        o["level"]=level; o["cve"]=cve; o["cveDate"]=cveDate;
        o["cvss"]=cvss; o["affected"]=affected;
        o["cveDesc"]=cveDesc; o["advice"]=advice;
        arr.append(o);
    };

    addVuln(1,
        "C:\\Windows\\Temp\\svchost32.exe", 9012,
        "EternalBlue (MS17-010 Exploit)",
        QString::fromUtf8("\xe5\x88\xa9\xe7\x94\xa8 SMB\xe5\x8d\x8f\xe8\xae\xae\xe8\xbf\x9c\xe7\xa8\x8b\xe4\xbb\xa3\xe7\xa0\x81\xe6\x89\xa7\xe8\xa1\x8c\xe6\xbc\x8f\xe6\xb4\x9e\xef\xbc\x8c\xe5\x90\x91\xe7\x9b\xae\xe6\xa0\x87\xe4\xb8\xbb\xe6\x9c\xba\xe5\x8f\x91\xe9\x80\x81\xe6\x81\xb6\xe6\x84\x8f\xe8\xb4\x9f\xe8\xbd\xbd\xe5\xb9\xb6\xe5\xbb\xba\xe7\xab\x8b\xe5\x8f\x8d\xe5\xbc\xb9 Shell\xef\xbc\x8c\xe5\xb1\x9e\xe9\xab\x98\xe5\x8d\xb1\xe7\xba\xa7\xe8\xbf\x9c\xe7\xa8\x8b\xe5\x85\xa5\xe4\xbe\xb5\xe8\xa1\x8c\xe4\xb8\xba"),
        "192.168.1.200", 49152, "192.168.1.100", 445, "SMB",
        QString::fromUtf8("\xe9\xab\x98\xe5\x8d\xb1"),
        "CVE-2017-0144", "2017-03-14", "9.3 (Critical)",
        "Windows SMBv1 (Windows XP / 7 / Server 2008)",
        QString::fromUtf8("Windows SMB \xe6\x9c\x8d\xe5\x8a\xa1\xe5\x99\xa8\xe5\xa4\x84\xe7\x90\x86\xe7\x89\xb9\xe5\xae\x9a\xe8\xaf\xb7\xe6\xb1\x82\xe6\x97\xb6\xe5\xad\x98\xe5\x9c\xa8\xe8\xbf\x9c\xe7\xa8\x8b\xe4\xbb\xa3\xe7\xa0\x81\xe6\x89\xa7\xe8\xa1\x8c\xe6\xbc\x8f\xe6\xb4\x9e"),
        QString::fromUtf8("1. \xe7\xab\x8b\xe5\x8d\xb3\xe5\xae\x89\xe8\xa3\x85 Microsoft \xe5\xae\x89\xe5\x85\xa8\xe5\x85\xac\xe5\x91\x8a MS17-010 \xe8\xa1\xa5\xe4\xb8\x81")
    );

    // 其余漏洞使用简化数据
    addVuln(2, "C:\\Windows\\Temp\\payload.exe", 9012,
        "Mimikatz (Pass-the-Hash)",
        QString::fromUtf8("\xe5\x88\xa9\xe7\x94\xa8 LSASS \xe5\x86\x85\xe5\xad\x98\xe8\xaf\xbb\xe5\x8f\x96\xe6\xbc\x8f\xe6\xb4\x9e\xe6\x8f\x90\xe5\x8f\x96\xe5\x87\xad\xe8\xaf\x81\xe4\xbf\xa1\xe6\x81\xaf"),
        "192.168.1.100", 49200, "192.168.1.150", 445, "SMB",
        QString::fromUtf8("\xe9\xab\x98\xe5\x8d\xb1"),
        "CVE-2021-36934", "2021-07-20", "7.8 (High)",
        "Windows 10 / Windows Server 2019",
        QString::fromUtf8("SAM \xe6\x95\xb0\xe6\x8d\xae\xe5\xba\x93\xe6\x9d\x83\xe9\x99\x90\xe9\x85\x8d\xe7\xbd\xae\xe4\xb8\x8d\xe5\xbd\x93"),
        QString::fromUtf8("\xe5\xae\x89\xe8\xa3\x85 KB5004442 \xe8\xa1\xa5\xe4\xb8\x81")
    );

    addVuln(3, "C:\\Windows\\Temp\\wuauclt32.exe", 3456,
        "PrintNightmare Exploit",
        QString::fromUtf8("\xe5\x88\xa9\xe7\x94\xa8 Windows \xe6\x89\x93\xe5\x8d\xb0\xe6\x9c\xba\xe6\x9c\x8d\xe5\x8a\xa1\xe6\xbc\x8f\xe6\xb4\x9e\xe8\xbf\x9c\xe7\xa8\x8b\xe5\x8a\xa0\xe8\xbd\xbd\xe6\x81\xb6\xe6\x84\x8f DLL"),
        "10.0.0.55", 52341, "192.168.1.100", 135, "TCP",
        QString::fromUtf8("\xe9\xab\x98\xe5\x8d\xb1"),
        "CVE-2021-34527", "2021-07-01", "8.8 (High)",
        "Windows Print Spooler",
        QString::fromUtf8("Print Spooler \xe6\x9c\xaa\xe8\xbf\x9b\xe8\xa1\x8c\xe5\x85\x85\xe5\x88\x86\xe6\x9d\x83\xe9\x99\x90\xe9\xaa\x8c\xe8\xaf\x81"),
        QString::fromUtf8("\xe5\xae\x89\xe8\xa3\x85 KB5004945 \xe8\xa1\xa5\xe4\xb8\x81")
    );

    addVuln(4, "C:\\Windows\\System32\\wuauclt32.exe", 3456,
        "Log4Shell Exploit",
        QString::fromUtf8("\xe5\x88\xa9\xe7\x94\xa8 Log4j2 JNDI \xe6\xb3\xa8\xe5\x85\xa5\xe6\xbc\x8f\xe6\xb4\x9e\xe8\xbf\x9c\xe7\xa8\x8b\xe4\xbb\xa3\xe7\xa0\x81\xe6\x89\xa7\xe8\xa1\x8c"),
        "10.0.0.88", 43210, "192.168.1.120", 8080, "HTTP",
        QString::fromUtf8("\xe4\xb8\xad\xe5\x8d\xb1"),
        "CVE-2021-44228", "2021-12-10", "10.0 (Critical)",
        "Apache Log4j2 2.0-beta9 - 2.14.1",
        QString::fromUtf8("Log4j2 \xe5\xad\x97\xe7\xac\xa6\xe4\xb8\xb2\xe5\xa4\x84\xe7\x90\x86 JNDI \xe6\xb3\xa8\xe5\x85\xa5"),
        QString::fromUtf8("\xe5\x8d\x87\xe7\xba\xa7 Log4j2 \xe8\x87\xb3 2.17.1")
    );

    addVuln(5, "C:\\Windows\\System32\\svchost.exe", 876,
        "BlueKeep Exploit (RDP)",
        QString::fromUtf8("\xe5\x88\xa9\xe7\x94\xa8 RDP \xe6\x9c\x8d\xe5\x8a\xa1\xe9\xa2\x84\xe8\xae\xa4\xe8\xaf\x81\xe8\xbf\x9c\xe7\xa8\x8b\xe4\xbb\xa3\xe7\xa0\x81\xe6\x89\xa7\xe8\xa1\x8c\xe6\xbc\x8f\xe6\xb4\x9e"),
        "185.220.101.45", 61234, "192.168.1.100", 3389, "TCP",
        QString::fromUtf8("\xe4\xb8\xad\xe5\x8d\xb1"),
        "CVE-2019-0708", "2019-05-14", "9.8 (Critical)",
        "Windows XP / Windows 7 / Server 2003/2008",
        QString::fromUtf8("RDP \xe9\xa2\x84\xe8\xae\xa4\xe8\xaf\x81\xe8\xbf\x9c\xe7\xa8\x8b\xe4\xbb\xa3\xe7\xa0\x81\xe6\x89\xa7\xe8\xa1\x8c"),
        QString::fromUtf8("\xe5\xae\x89\xe8\xa3\x85 KB4499175 \xe8\xa1\xa5\xe4\xb8\x81")
    );

    return QJsonDocument(arr).toJson(QJsonDocument::Compact);
}

QString AppBridge::getProcDetail(const QString &procName)
{
    // 返回进程详情（模块/线程/句柄）
    QJsonObject obj;
    if (procName == "svchost32.exe") {
        obj["pid"] = 9012; obj["ppid"] = 876;
        obj["cpu"] = "8.6%"; obj["mem"] = "96 MB";
        obj["threads"] = 6; obj["handles"] = 88;
        obj["publisher"] = "未知";
        obj["path"] = "C:\\Windows\\Temp\\svchost32.exe";
        obj["mtime"] = "2025-11-20 02:13:44";
        obj["sign"] = "未签名";
        obj["ctime"] = "2025-11-20 09:41:00";
        obj["cmdline"] = "C:\\Windows\\Temp\\svchost32.exe -s NetworkService";
        obj["risk"] = "danger";

        QJsonArray mods;
        auto addMod = [&](const QString &n, const QString &p,
                          const QString &pub, const QString &mt,
                          const QString &sz, const QString &sg) {
            QJsonObject m;
            m["name"]=n; m["path"]=p; m["publisher"]=pub;
            m["mtime"]=mt; m["size"]=sz; m["sign"]=sg;
            mods.append(m);
        };
        addMod("ntdll.dll","C:\\Windows\\System32\\ntdll.dll",
               "Microsoft Corporation","2024-01-15","1.9 MB","green:已签名");
        addMod("kernel32.dll","C:\\Windows\\System32\\kernel32.dll",
               "Microsoft Corporation","2024-01-15","0.8 MB","green:已签名");
        addMod("ws2_32.dll","C:\\Windows\\System32\\ws2_32.dll",
               "Microsoft Corporation","2024-01-15","0.3 MB","green:已签名");
        addMod("inject.dll","C:\\Windows\\Temp\\inject.dll",
               "未知","2025-11-20","0.1 MB","red:未签名");
        addMod("payload.dll","C:\\Windows\\Temp\\payload.dll",
               "未知","2025-11-20","0.2 MB","red:未签名");
        obj["modules"] = mods;

        QJsonArray thrs;
        auto addThr = [&](int tid, const QString &state, int pri,
                          const QString &cpu, const QString &addr,
                          const QString &mod, const QString &ct) {
            QJsonObject t;
            t["tid"]=tid; t["state"]=state; t["priority"]=pri;
            t["cpu"]=cpu; t["addr"]=addr; t["module"]=mod; t["ctime"]=ct;
            thrs.append(t);
        };
        addThr(9016,"运行",13,"5.2%","0x00007FF800001000","svchost32.exe","2025-11-20 09:41:00");
        addThr(9020,"运行",10,"2.1%","0x00007FF800002000","inject.dll","2025-11-20 09:41:01");
        addThr(9024,"运行",8,"1.3%","0x00007FF800003000","ws2_32.dll","2025-11-20 09:41:02");
        obj["threads_list"] = thrs;

        QJsonArray hdls;
        auto addHdl = [&](const QString &val, const QString &type,
                          const QString &access, const QString &path) {
            QJsonObject h;
            h["value"]=val; h["type"]=type; h["access"]=access; h["path"]=path;
            hdls.append(h);
        };
        addHdl("0x0004","文件","读/写","C:\\Windows\\Temp\\svchost32.exe");
        addHdl("0x0008","文件","读/写","C:\\Windows\\Temp\\payload.dll");
        addHdl("0x000C","套接字","读/写","TCP 192.168.1.100:49152 → 185.220.101.45:4444");
        addHdl("0x0010","注册表","读/写","HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        addHdl("0x0014","进程","全部","explorer.exe (PID: 1234) — 注入目标");
        obj["handles"] = hdls;
    } else {
        // 通用进程数据
        obj["pid"] = 0; obj["ppid"] = 0;
        obj["cpu"] = "0.0%"; obj["mem"] = "0 MB";
        obj["threads"] = 0; obj["handles"] = 0;
        obj["publisher"] = "未知"; obj["path"] = "";
        obj["risk"] = "normal";
        obj["modules"] = QJsonArray();
        obj["threads_list"] = QJsonArray();
        obj["handles"] = QJsonArray();
    }
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}
