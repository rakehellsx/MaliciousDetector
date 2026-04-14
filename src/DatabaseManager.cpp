#include "DatabaseManager.h"
#include <QStandardPaths>
#include <QDir>
#include <QDebug>
#include <QSqlRecord>
#include <QVariant>
#include <QJsonDocument>
#include <QJsonArray>

DatabaseManager* DatabaseManager::m_instance = nullptr;

DatabaseManager* DatabaseManager::instance()
{
    if (!m_instance) m_instance = new DatabaseManager();
    return m_instance;
}

DatabaseManager::DatabaseManager(QObject *parent) : QObject(parent) {}

bool DatabaseManager::init(const QString &dbPath)
{
    QString path = dbPath;
    if (path.isEmpty()) {
        QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        QDir().mkpath(dir);
        path = dir + "/malware_detector.db";
    }
    m_dbPath = path;

    m_db = QSqlDatabase::addDatabase("QSQLITE", "main_conn");
    m_db.setDatabaseName(path);
    if (!m_db.open()) {
        m_lastError = m_db.lastError().text();
        return false;
    }
    return createTables();
}

void DatabaseManager::close()
{
    if (m_db.isOpen()) m_db.close();
}

// ── 工具函数 ─────────────────────────────────────────────────────────────────

QVariantList DatabaseManager::execSelect(const QString &sql, const QVariantList &binds)
{
    QVariantList result;
    QSqlQuery q(m_db);
    q.prepare(sql);
    for (int i = 0; i < binds.size(); ++i) q.addBindValue(binds[i]);
    if (!q.exec()) {
        m_lastError = q.lastError().text();
        qWarning() << "DB query error:" << m_lastError << sql;
        return result;
    }
    QSqlRecord rec = q.record();
    int cols = rec.count();
    while (q.next()) {
        QVariantMap row;
        for (int c = 0; c < cols; ++c)
            row[rec.fieldName(c)] = q.value(c);
        result << row;
    }
    return result;
}

QVariantMap DatabaseManager::execSelectOne(const QString &sql, const QVariantList &binds)
{
    QVariantList rows = execSelect(sql, binds);
    return rows.isEmpty() ? QVariantMap() : rows.first().toMap();
}

// ── 建表 ─────────────────────────────────────────────────────────────────────

bool DatabaseManager::createTables()
{
    QSqlQuery q(m_db);
    q.exec("PRAGMA journal_mode=WAL");
    q.exec("PRAGMA foreign_keys=ON");

    // 1. 系统基本信息
    q.exec(R"(CREATE TABLE IF NOT EXISTS sys_info (
        id    INTEGER PRIMARY KEY AUTOINCREMENT,
        key   TEXT NOT NULL,
        value TEXT,
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 2. 网络信息
    q.exec(R"(CREATE TABLE IF NOT EXISTS net_info (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT,
        ip         TEXT,
        mask       TEXT,
        gateway    TEXT,
        mac        TEXT,
        status     TEXT,
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 3. 硬盘信息
    q.exec(R"(CREATE TABLE IF NOT EXISTS disk_info (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        drive       TEXT,
        type        TEXT,
        filesystem  TEXT,
        total_gb    REAL,
        free_gb     REAL,
        used_pct    REAL,
        serial      TEXT,
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 4. 进程信息
    q.exec(R"(CREATE TABLE IF NOT EXISTS process_info (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        pid         INTEGER,
        name        TEXT,
        path        TEXT,
        user        TEXT,
        cpu_pct     REAL,
        mem_mb      REAL,
        status      TEXT,
        risk        TEXT DEFAULT 'clean',
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 5. 端口信息
    q.exec(R"(CREATE TABLE IF NOT EXISTS port_info (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        protocol     TEXT,
        local_ip     TEXT,
        local_port   INTEGER,
        remote_ip    TEXT,
        remote_port  INTEGER,
        state        TEXT,
        process_name TEXT,
        pid          INTEGER,
        risk         TEXT DEFAULT 'clean',
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 6. 自启动项
    q.exec(R"(CREATE TABLE IF NOT EXISTS autorun_info (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        type        TEXT NOT NULL,  -- reg/folder/rightclick/debugger
        name        TEXT,
        reg_path    TEXT,
        value       TEXT,
        cmd         TEXT,
        publisher   TEXT,
        risk        TEXT DEFAULT 'clean',
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 7. 计划任务
    q.exec(R"(CREATE TABLE IF NOT EXISTS scheduled_task (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT,
        path        TEXT,
        trigger     TEXT,
        action      TEXT,
        status      TEXT,
        last_run    TEXT,
        risk        TEXT DEFAULT 'clean',
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 8. 驱动信息
    q.exec(R"(CREATE TABLE IF NOT EXISTS driver_info (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT,
        type         TEXT,
        publisher    TEXT,
        modified_time TEXT,
        path         TEXT,
        is_signed    INTEGER DEFAULT 1,
        risk         TEXT DEFAULT 'clean',
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 9. 共享资源
    q.exec(R"(CREATE TABLE IF NOT EXISTS shared_resource (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT,
        path        TEXT,
        type        TEXT,
        permission  TEXT,
        connected   INTEGER DEFAULT 0,
        risk        TEXT DEFAULT 'clean',
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 10. 浏览器插件
    q.exec(R"(CREATE TABLE IF NOT EXISTS browser_plugin (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        browser     TEXT,
        name        TEXT,
        version     TEXT,
        publisher   TEXT,
        status      TEXT,
        risk        TEXT DEFAULT 'clean',
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 11. 内存映像 - 内存状态
    q.exec(R"(CREATE TABLE IF NOT EXISTS memory_status (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        total_mb     INTEGER,
        used_mb      INTEGER,
        avail_mb     INTEGER,
        virtual_mb   INTEGER,
        page_file    TEXT,
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 12. 内存映像 - 内核模块
    q.exec(R"(CREATE TABLE IF NOT EXISTS kernel_module (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT,
        base_address TEXT,
        image_size   TEXT,
        flags        TEXT,
        idx          INTEGER,
        path         TEXT,
        is_trusted   INTEGER DEFAULT 1,
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 13. 内存映像 - 进程内存映射
    q.exec(R"(CREATE TABLE IF NOT EXISTS process_memory (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        name              TEXT,
        pid               INTEGER,
        private_mb        INTEGER,
        working_set_mb    INTEGER,
        virtual_mb        INTEGER,
        suspicious_inject INTEGER DEFAULT 0,
        collected_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 14. 静态检测结果
    q.exec(R"(CREATE TABLE IF NOT EXISTS static_scan (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path    TEXT NOT NULL,
        file_name    TEXT,
        file_size    INTEGER,
        file_type    TEXT,
        md5          TEXT,
        sha1         TEXT,
        sha256       TEXT,
        compile_time TEXT,
        publisher    TEXT,
        pe_info      TEXT,
        strings_info TEXT,
        rule_hits    TEXT,
        risk_level   TEXT DEFAULT 'clean',
        virus_name   TEXT,
        conclusion   TEXT,
        scan_time    TEXT DEFAULT (datetime('now','localtime'))
    ))");
    q.exec("ALTER TABLE static_scan ADD COLUMN virus_name TEXT");
    q.exec("ALTER TABLE static_scan ADD COLUMN compile_time TEXT");
    q.exec("ALTER TABLE static_scan ADD COLUMN publisher TEXT");

    // 15. 数字证书检测
    q.exec(R"(CREATE TABLE IF NOT EXISTS cert_scan (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path        TEXT NOT NULL,
        has_signature    INTEGER DEFAULT 0,
        signature_valid  INTEGER DEFAULT 0,
        file_tampered    INTEGER DEFAULT 0,
        subject          TEXT,
        issuer           TEXT,
        serial_number    TEXT,
        not_before       TEXT,
        not_after        TEXT,
        not_expired      INTEGER DEFAULT 1,
        hash_algorithm   TEXT,
        thumbprint_sha1  TEXT,
        thumbprint_sha256 TEXT,
        verify_result    TEXT,
        scan_time        TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 16. 动态行为检测
    q.exec(R"(CREATE TABLE IF NOT EXISTS dynamic_scan (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        sample_path   TEXT,
        behavior_type TEXT NOT NULL,
        action_type   TEXT,
        source_proc   TEXT,
        target_path   TEXT,
        detail        TEXT,
        risk_level    TEXT DEFAULT 'clean',
        parent_pid    INTEGER DEFAULT 0,
        pid           INTEGER DEFAULT 0,
        scan_time     TEXT DEFAULT (datetime('now','localtime'))
    ))");
    q.exec("ALTER TABLE dynamic_scan ADD COLUMN parent_pid INTEGER DEFAULT 0");
    q.exec("ALTER TABLE dynamic_scan ADD COLUMN pid INTEGER DEFAULT 0");

    // 17. 文件关联检测
    q.exec(R"(CREATE TABLE IF NOT EXISTS file_assoc_scan (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ext          TEXT,
        assoc_type   TEXT,
        original_cmd TEXT,
        current_cmd  TEXT,
        risk_level   TEXT DEFAULT 'clean',
        scan_time    TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 18. 样本提取
    q.exec(R"(CREATE TABLE IF NOT EXISTS sample_extract (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        source_path    TEXT NOT NULL,
        extract_type   TEXT,
        sample_path    TEXT,
        md5            TEXT,
        sha256         TEXT,
        original_mtime TEXT,
        original_ctime TEXT,
        note           TEXT,
        extract_time   TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 19. 操作日志
    q.exec(R"(CREATE TABLE IF NOT EXISTS audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        role       TEXT NOT NULL,
        username   TEXT NOT NULL,
        action     TEXT NOT NULL,
        detail     TEXT,
        result     TEXT DEFAULT 'success',
        ip_address TEXT DEFAULT '',
        timestamp  TEXT DEFAULT (datetime('now','localtime'))
    ))");
    q.exec("ALTER TABLE audit_log ADD COLUMN ip_address TEXT DEFAULT ''");

    // 20. 系统设置
    q.exec(R"(CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT
    ))");

    // 21. 用户管理
    q.exec(R"(CREATE TABLE IF NOT EXISTS users (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        username   TEXT NOT NULL UNIQUE,
        role       TEXT NOT NULL,
        status     TEXT DEFAULT 'active',
        last_login TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 22. 白名单
    q.exec(R"(CREATE TABLE IF NOT EXISTS whitelist (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        path       TEXT NOT NULL,
        md5        TEXT,
        note       TEXT,
        added_by   TEXT,
        added_at   TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 23. 自定义规则
    q.exec(R"(CREATE TABLE IF NOT EXISTS custom_rules (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        rule_type   TEXT,
        pattern     TEXT,
        description TEXT,
        enabled     INTEGER DEFAULT 1,
        created_at  TEXT DEFAULT (datetime('now','localtime'))
    ))");

    // 默认设置
    QSqlQuery sq(m_db);
    sq.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)");
    QList<QPair<QString,QString>> defaults = {
        {"dll_path",           "basic.dll"},
        {"db_path",            "malware_detector.db"},
        {"virus_db_version",   "20251120"},
        {"virus_db_date",      "2025-11-20"},
        {"auto_scan",          "false"},
        {"scan_on_startup",    "false"},
        {"realtime_protect",   "false"},
        {"log_retention_days", "90"},
        {"report_output_dir",  "./reports"},
        {"update_source",      "http://update.internal/virusdb"},
        {"update_freq",        "每天更新"},
        {"auto_update",        "true"},
        {"scan_depth",         "全盘扫描"},
        {"scan_compress",      "true"},
        {"scan_hidden",        "true"},
        {"product_version",    "V3.0.20251120"},
        {"product_name",       "恶意代码辅助检测系统"},
        {"vendor",             "国家保密科技测评中心认证产品"},
    };
    for (auto &kv : defaults) {
        sq.bindValue(0, kv.first);
        sq.bindValue(1, kv.second);
        sq.exec();
    }

    // 首次初始化插入测试数据
    QSqlQuery chk(m_db);
    chk.exec("SELECT COUNT(*) FROM sys_info");
    if (chk.next() && chk.value(0).toInt() == 0) {
        insertTestData();
    }
    return true;
}

// ── 测试数据 ─────────────────────────────────────────────────────────────────

void DatabaseManager::insertTestData()
{
    QSqlQuery q(m_db);

    // ── 1. 系统基本信息 ──────────────────────────────────────────────────────
    QStringList sysKeys = {
        "操作系统", "系统版本", "计算机名称", "域名", "工作组",
        "系统目录", "Windows目录", "CPU型号", "CPU核心数", "物理内存",
        "系统启动时间", "当前用户", "系统语言", "时区", "BIOS版本"
    };
    QStringList sysVals = {
        "Windows 10 专业版 64位", "10.0.19045 Build 19045", "SECURE-PC-001",
        "WORKGROUP", "WORKGROUP", "C:\\Windows\\System32", "C:\\Windows",
        "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz", "8核16线程", "16,384 MB",
        "2025-11-20 08:01:22", "Administrator", "中文(简体,中国)", "UTC+8:00",
        "LENOVO-1.0.0 (2021/06/15)"
    };
    q.prepare("INSERT INTO sys_info(key,value) VALUES(?,?)");
    for (int i = 0; i < sysKeys.size(); ++i) {
        q.bindValue(0, sysKeys[i]);
        q.bindValue(1, sysVals[i]);
        q.exec();
    }

    // ── 2. 网络信息 ──────────────────────────────────────────────────────────
    struct NetRow { QString name,ip,mask,gw,mac,status; };
    QList<NetRow> nets = {
        {"以太网",   "192.168.1.100", "255.255.255.0", "192.168.1.1",  "00:1A:2B:3C:4D:5E", "已连接"},
        {"本地回环", "127.0.0.1",     "255.0.0.0",     "--",           "--",                 "已连接"},
        {"WLAN",    "10.0.0.105",    "255.255.0.0",   "10.0.0.1",     "A4:C3:F0:12:34:56", "已连接"},
    };
    q.prepare("INSERT INTO net_info(name,ip,mask,gateway,mac,status) VALUES(?,?,?,?,?,?)");
    for (auto &n : nets) {
        q.bindValue(0,n.name); q.bindValue(1,n.ip); q.bindValue(2,n.mask);
        q.bindValue(3,n.gw);   q.bindValue(4,n.mac); q.bindValue(5,n.status);
        q.exec();
    }

    // ── 3. 硬盘信息 ──────────────────────────────────────────────────────────
    struct DiskRow { QString drive,type,fs,serial; double total,free,used; };
    QList<DiskRow> disks = {
        {"C:", "固态硬盘(SSD)", "NTFS", "WD-WX31A73E5E5E", 476.8, 212.3, 55.4},
        {"D:", "机械硬盘(HDD)", "NTFS", "WD-WX41A84F6F6F", 931.5, 620.8, 33.4},
        {"E:", "移动硬盘",      "NTFS", "USB-20230901",     119.2,  89.1, 25.3},
    };
    q.prepare("INSERT INTO disk_info(drive,type,filesystem,total_gb,free_gb,used_pct,serial) VALUES(?,?,?,?,?,?,?)");
    for (auto &d : disks) {
        q.bindValue(0,d.drive); q.bindValue(1,d.type); q.bindValue(2,d.fs);
        q.bindValue(3,d.total); q.bindValue(4,d.free); q.bindValue(5,d.used);
        q.bindValue(6,d.serial); q.exec();
    }

    // ── 4. 进程信息 ──────────────────────────────────────────────────────────
    struct ProcRow { int pid; QString name,path,user; double cpu,mem; QString status,risk; };
    QList<ProcRow> procs = {
        {4,    "System",         "NT Kernel",                                   "SYSTEM",        0.1,  0.1,  "运行中","clean"},
        {688,  "smss.exe",       "C:\\Windows\\System32\\smss.exe",             "SYSTEM",        0.0,  0.5,  "运行中","clean"},
        {1234, "explorer.exe",   "C:\\Windows\\explorer.exe",                   "Administrator", 1.2,  48.3, "运行中","clean"},
        {5678, "chrome.exe",     "C:\\Program Files\\Google\\Chrome\\chrome.exe","Administrator",8.5, 256.0, "运行中","clean"},
        {9012, "svchost32.exe",  "C:\\Windows\\Temp\\svchost32.exe",            "SYSTEM",        3.2,  96.0, "运行中","high"},
        {3456, "wuauclt32.exe",  "C:\\Windows\\Temp\\wuauclt32.exe",            "Administrator", 2.1, 128.0, "运行中","medium"},
        {876,  "svchost.exe",    "C:\\Windows\\System32\\svchost.exe",          "NETWORK SERVICE",0.3, 32.0, "运行中","clean"},
        {2048, "notepad.exe",    "C:\\Windows\\System32\\notepad.exe",          "Administrator", 0.0,   8.2, "运行中","clean"},
    };
    q.prepare("INSERT INTO process_info(pid,name,path,user,cpu_pct,mem_mb,status,risk) VALUES(?,?,?,?,?,?,?,?)");
    for (auto &p : procs) {
        q.bindValue(0,p.pid); q.bindValue(1,p.name); q.bindValue(2,p.path);
        q.bindValue(3,p.user); q.bindValue(4,p.cpu); q.bindValue(5,p.mem);
        q.bindValue(6,p.status); q.bindValue(7,p.risk); q.exec();
    }

    // ── 5. 端口信息 ──────────────────────────────────────────────────────────
    struct PortRow { QString proto,lip; int lport; QString rip; int rport; QString state,proc; int pid; QString risk; };
    QList<PortRow> ports = {
        {"TCP","0.0.0.0",      135,  "",              0,   "LISTENING",  "svchost.exe",    876,  "clean"},
        {"TCP","0.0.0.0",      445,  "",              0,   "LISTENING",  "System",         4,    "clean"},
        {"TCP","192.168.1.100",49152,"192.168.1.200", 443, "ESTABLISHED","chrome.exe",     5678, "clean"},
        {"TCP","192.168.1.100",49200,"185.220.101.5", 4444,"ESTABLISHED","svchost32.exe",  9012, "high"},
        {"TCP","0.0.0.0",      8080, "",              0,   "LISTENING",  "wuauclt32.exe",  3456, "medium"},
        {"UDP","0.0.0.0",      5353, "",              0,   "LISTENING",  "chrome.exe",     5678, "clean"},
        {"TCP","127.0.0.1",    3306, "",              0,   "LISTENING",  "mysqld.exe",     7890, "clean"},
    };
    q.prepare("INSERT INTO port_info(protocol,local_ip,local_port,remote_ip,remote_port,state,process_name,pid,risk) VALUES(?,?,?,?,?,?,?,?,?)");
    for (auto &p : ports) {
        q.bindValue(0,p.proto); q.bindValue(1,p.lip); q.bindValue(2,p.lport);
        q.bindValue(3,p.rip);   q.bindValue(4,p.rport); q.bindValue(5,p.state);
        q.bindValue(6,p.proc);  q.bindValue(7,p.pid); q.bindValue(8,p.risk); q.exec();
    }

    // ── 6. 自启动项 ──────────────────────────────────────────────────────────
    // 注册表启动项
    struct AutorunRow { QString type,name,regPath,value,cmd,publisher,risk; };
    QList<AutorunRow> autoruns = {
        {"reg","SecurityUpdate","HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "SecurityUpdate","C:\\Windows\\Temp\\svchost32.exe /silent","未知","high"},
        {"reg","OneDrive","HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "OneDrive","C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background","Microsoft Corporation","clean"},
        {"reg","WinRAR","HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "WinRAR","C:\\Program Files\\WinRAR\\WinRAR.exe","win.rar GmbH","clean"},
        {"folder","MalwareLoader","C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
         "","C:\\Users\\Public\\Documents\\loader.exe","未知","high"},
        {"folder","OneDriveStarter","C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
         "","C:\\Program Files\\Microsoft OneDrive\\OneDriveStarter.exe","Microsoft Corporation","clean"},
        {"rightclick","打开方式","HKCR\\*\\shell\\OpenWithNotepad",
         "","C:\\Windows\\Temp\\svchost32.exe \"%1\"","未知","high"},
        {"rightclick","用记事本打开","HKCR\\*\\shell\\Open with Notepad",
         "","C:\\Windows\\System32\\notepad.exe \"%1\"","Microsoft Corporation","clean"},
        {"debugger","svchost.exe","HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe",
         "","C:\\Windows\\Temp\\svchost32.exe","未知","high"},
    };
    q.prepare("INSERT INTO autorun_info(type,name,reg_path,value,cmd,publisher,risk) VALUES(?,?,?,?,?,?,?)");
    for (auto &a : autoruns) {
        q.bindValue(0,a.type); q.bindValue(1,a.name); q.bindValue(2,a.regPath);
        q.bindValue(3,a.value); q.bindValue(4,a.cmd); q.bindValue(5,a.publisher);
        q.bindValue(6,a.risk); q.exec();
    }

    // ── 7. 计划任务 ──────────────────────────────────────────────────────────
    struct TaskRow { QString name,path,trigger,action,status,lastRun,risk; };
    QList<TaskRow> tasks = {
        {"MalwareTask","\\Microsoft\\Windows\\MalwareTask","每天 03:00",
         "C:\\Windows\\Temp\\svchost32.exe /run","就绪","2025-11-19 03:00:01","high"},
        {"WindowsDefenderCache","\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance",
         "触发器：系统空闲","C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MpCmdRun.exe",
         "就绪","2025-11-20 10:15:33","clean"},
        {"GoogleUpdateTask","\\GoogleUpdate\\GoogleUpdateTaskMachineCore","每小时",
         "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c","就绪","2025-11-20 09:00:00","clean"},
        {"DataCollector","\\Microsoft\\Windows\\DataCollector","每5分钟",
         "C:\\Windows\\Temp\\wuauclt32.exe --collect","运行中","2025-11-20 09:41:00","medium"},
    };
    q.prepare("INSERT INTO scheduled_task(name,path,trigger,action,status,last_run,risk) VALUES(?,?,?,?,?,?,?)");
    for (auto &t : tasks) {
        q.bindValue(0,t.name); q.bindValue(1,t.path); q.bindValue(2,t.trigger);
        q.bindValue(3,t.action); q.bindValue(4,t.status); q.bindValue(5,t.lastRun);
        q.bindValue(6,t.risk); q.exec();
    }

    // ── 8. 驱动信息 ──────────────────────────────────────────────────────────
    struct DriverRow { QString name,type,publisher,modTime,path,risk; int isSigned; };
    QList<DriverRow> drivers = {
        {"ntfs.sys","实体硬件","Microsoft Corporation","2025-08-12 10:22:11",
         "C:\\Windows\\System32\\drivers\\ntfs.sys","clean",1},
        {"tcpip.sys","实体硬件","Microsoft Corporation","2025-09-01 08:15:44",
         "C:\\Windows\\System32\\drivers\\tcpip.sys","clean",1},
        {"hiddrv.sys","虚拟硬件","未知","2025-11-18 23:59:01",
         "C:\\Windows\\System32\\drivers\\hiddrv.sys","high",0},
        {"ndis.sys","实体硬件","Microsoft Corporation","2025-07-20 14:30:00",
         "C:\\Windows\\System32\\drivers\\ndis.sys","clean",1},
        {"vmbus.sys","虚拟硬件","Microsoft Corporation","2025-06-15 09:00:00",
         "C:\\Windows\\System32\\drivers\\vmbus.sys","clean",1},
        {"rootkit_drv.sys","虚拟硬件","未知","2025-11-19 01:30:00",
         "C:\\Windows\\System32\\drivers\\rootkit_drv.sys","high",0},
    };
    q.prepare("INSERT INTO driver_info(name,type,publisher,modified_time,path,is_signed,risk) VALUES(?,?,?,?,?,?,?)");
    for (auto &d : drivers) {
        q.bindValue(0,d.name); q.bindValue(1,d.type); q.bindValue(2,d.publisher);
        q.bindValue(3,d.modTime); q.bindValue(4,d.path); q.bindValue(5,d.isSigned);
        q.bindValue(6,d.risk); q.exec();
    }

    // ── 9. 共享资源 ──────────────────────────────────────────────────────────
    struct ShareRow { QString name,path,type,perm,risk; int conn; };
    QList<ShareRow> shares = {
        {"ADMIN$","C:\\Windows","管理共享","完全控制","clean",0},
        {"C$","C:\\","默认共享","完全控制","clean",0},
        {"SharedDocs","D:\\Documents\\Shared","用户共享","读写","clean",2},
        {"HiddenShare$","C:\\Windows\\Temp","隐藏共享","完全控制","high",1},
        {"IPC$","","IPC共享","只读","clean",0},
    };
    q.prepare("INSERT INTO shared_resource(name,path,type,permission,connected,risk) VALUES(?,?,?,?,?,?)");
    for (auto &s : shares) {
        q.bindValue(0,s.name); q.bindValue(1,s.path); q.bindValue(2,s.type);
        q.bindValue(3,s.perm); q.bindValue(4,s.conn); q.bindValue(5,s.risk); q.exec();
    }

    // ── 10. 浏览器插件 ───────────────────────────────────────────────────────
    struct PluginRow { QString browser,name,version,publisher,status,risk; };
    QList<PluginRow> plugins = {
        {"Chrome","AdBlock","4.1.2","AdBlock Inc.","已启用","clean"},
        {"Chrome","Tampermonkey","4.18.1","Jan Biniok","已启用","clean"},
        {"Chrome","MaliciousExtension","1.0.0","未知","已启用","high"},
        {"Edge","Microsoft Editor","3.0.12","Microsoft","已启用","clean"},
        {"Edge","UnknownAddon","2.3.1","未知","已启用","medium"},
        {"Firefox","uBlock Origin","1.52.2","Raymond Hill","已启用","clean"},
        {"Firefox","SuspiciousPlugin","0.9.1","未知","已启用","high"},
    };
    q.prepare("INSERT INTO browser_plugin(browser,name,version,publisher,status,risk) VALUES(?,?,?,?,?,?)");
    for (auto &p : plugins) {
        q.bindValue(0,p.browser); q.bindValue(1,p.name); q.bindValue(2,p.version);
        q.bindValue(3,p.publisher); q.bindValue(4,p.status); q.bindValue(5,p.risk); q.exec();
    }

    // ── 11. 内存映像 - 状态 ──────────────────────────────────────────────────
    q.exec("INSERT INTO memory_status(total_mb,used_mb,avail_mb,virtual_mb,page_file) "
           "VALUES(16384,6348,10036,32768,'C:\\pagefile.sys (2048 MB)')");

    // ── 12. 内核模块 ─────────────────────────────────────────────────────────
    struct KernelRow { QString name,base,size,flags,path; int idx,trusted; };
    QList<KernelRow> kmods = {
        {"ntoskrnl.exe","0xFFFFF80000000000","8.2 MB","0x0","C:\\Windows\\System32\\ntoskrnl.exe",1,1},
        {"hal.dll",     "0xFFFFF80001200000","0.5 MB","0x0","C:\\Windows\\System32\\hal.dll",2,1},
        {"hiddrv.sys",  "0xFFFFF88003A00000","0.1 MB","0x4","C:\\Windows\\System32\\drivers\\hiddrv.sys",87,0},
        {"win32k.sys",  "0xFFFFF96000000000","2.1 MB","0x0","C:\\Windows\\System32\\win32k.sys",12,1},
        {"ndis.sys",    "0xFFFFF88001A00000","1.3 MB","0x0","C:\\Windows\\System32\\drivers\\ndis.sys",24,1},
    };
    q.prepare("INSERT INTO kernel_module(name,base_address,image_size,flags,path,idx,is_trusted) VALUES(?,?,?,?,?,?,?)");
    for (auto &k : kmods) {
        q.bindValue(0,k.name); q.bindValue(1,k.base); q.bindValue(2,k.size);
        q.bindValue(3,k.flags); q.bindValue(4,k.path); q.bindValue(5,k.idx);
        q.bindValue(6,k.trusted); q.exec();
    }

    // ── 13. 进程内存映射 ─────────────────────────────────────────────────────
    struct ProcMemRow { QString name; int pid,priv,ws,virt,inject; };
    QList<ProcMemRow> pmems = {
        {"chrome.exe",     5678, 256, 312, 1024, 0},
        {"svchost32.exe",  9012,  96, 128,  256, 1},
        {"explorer.exe",   1234,  48,  72,  512, 0},
        {"wuauclt32.exe",  3456, 128, 156,  384, 0},
        {"svchost.exe",     876,  32,  48,  256, 0},
    };
    q.prepare("INSERT INTO process_memory(name,pid,private_mb,working_set_mb,virtual_mb,suspicious_inject) VALUES(?,?,?,?,?,?)");
    for (auto &p : pmems) {
        q.bindValue(0,p.name); q.bindValue(1,p.pid); q.bindValue(2,p.priv);
        q.bindValue(3,p.ws); q.bindValue(4,p.virt); q.bindValue(5,p.inject); q.exec();
    }

    // ── 14. 静态检测 ─────────────────────────────────────────────────────────
    struct StaticRow {
        QString path,name,type,md5,sha256,compileTime,publisher,peInfo,strings,ruleHits,risk,virus,conclusion;
        int size;
    };
    QList<StaticRow> statics = {
        {
            "C:\\Windows\\Temp\\svchost32.exe", "svchost32.exe", "PE32 可执行文件(EXE)",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b",
            "2025-11-19 23:58:01", "未知（无版本信息）",
            "{\"arch\":\"x86\",\"sections\":[{\"name\":\".text\",\"vsize\":\"0x8200\",\"rsize\":\"0x8400\"},{\"name\":\".data\",\"vsize\":\"0x1200\",\"rsize\":\"0x1400\"},{\"name\":\".rsrc\",\"vsize\":\"0x800\",\"rsize\":\"0x1000\"}],\"imports\":[\"kernel32.dll\",\"ws2_32.dll\",\"advapi32.dll\"],\"entry_point\":\"0x1000\",\"image_base\":\"0x400000\"}",
            "[\"CreateRemoteThread\",\"VirtualAllocEx\",\"WriteProcessMemory\",\"cmd.exe /c\",\"185.220.101.5\",\"4444\",\"backdoor\",\"shell\"]",
            "[{\"rule\":\"Trojan.Win32.Backdoor\",\"severity\":\"high\",\"desc\":\"匹配后门木马特征码\"},{\"rule\":\"Network.SuspiciousConnect\",\"severity\":\"high\",\"desc\":\"连接可疑C2地址\"}]",
            "high", "Trojan.Win32.Backdoor.Generic", "高危 — 疑似远控木马", 98304
        },
        {
            "C:\\Windows\\Temp\\payload.dll", "payload.dll", "PE32 动态链接库(DLL)",
            "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7", "4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c",
            "2025-11-18 15:22:33", "未知",
            "{\"arch\":\"x86\",\"sections\":[{\"name\":\".text\",\"vsize\":\"0x4100\",\"rsize\":\"0x4200\"},{\"name\":\".data\",\"vsize\":\"0x800\",\"rsize\":\"0x1000\"}],\"imports\":[\"kernel32.dll\",\"ntdll.dll\"],\"entry_point\":\"0x2000\",\"image_base\":\"0x10000000\"}",
            "[\"NtCreateThread\",\"ZwWriteVirtualMemory\",\"LoadLibraryA\",\"GetProcAddress\",\"inject\",\"hook\"]",
            "[{\"rule\":\"Inject.DLL.Suspicious\",\"severity\":\"medium\",\"desc\":\"DLL注入特征\"},{\"rule\":\"AntiDebug.NtQuery\",\"severity\":\"medium\",\"desc\":\"反调试技术\"}]",
            "medium", "Trojan.Win32.Inject.DLL", "中危 — 疑似注入DLL", 45056
        },
        {
            "C:\\Program Files\\Google\\Chrome\\chrome.exe", "chrome.exe", "PE32+ 可执行文件(EXE)",
            "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8", "5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
            "2025-10-15 08:00:00", "Google LLC",
            "{\"arch\":\"x64\",\"sections\":[{\"name\":\".text\",\"vsize\":\"0x1200000\",\"rsize\":\"0x1200200\"},{\"name\":\".data\",\"vsize\":\"0x80000\",\"rsize\":\"0x80200\"}],\"imports\":[\"kernel32.dll\",\"user32.dll\",\"gdi32.dll\"],\"entry_point\":\"0x1000\",\"image_base\":\"0x140000000\"}",
            "[\"CreateWindow\",\"LoadLibrary\",\"GetProcAddress\",\"socket\",\"connect\"]",
            "[]",
            "clean", "", "安全 — 正版浏览器程序", 102400000
        },
        {
            "C:\\Users\\Administrator\\Desktop\\report.pdf.exe", "report.pdf.exe", "PE32 可执行文件(EXE)",
            "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", "6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e",
            "2025-11-15 09:30:00", "未知",
            "{\"arch\":\"x86\",\"sections\":[{\"name\":\".text\",\"vsize\":\"0x3000\",\"rsize\":\"0x3200\"},{\"name\":\".data\",\"vsize\":\"0x500\",\"rsize\":\"0x600\"}],\"imports\":[\"kernel32.dll\",\"shell32.dll\"],\"entry_point\":\"0x1000\",\"image_base\":\"0x400000\"}",
            "[\"ShellExecute\",\"WinExec\",\"CreateProcess\",\"PDF\",\"document\",\"双扩展名\"]",
            "[{\"rule\":\"Disguise.DoubleExt\",\"severity\":\"high\",\"desc\":\"双扩展名伪装PDF文件\"},{\"rule\":\"Dropper.Suspicious\",\"severity\":\"high\",\"desc\":\"疑似下载器\"}]",
            "high", "Trojan.Win32.Dropper.Disguise", "高危 — 伪装PDF的木马程序", 18432
        },
    };
    q.prepare("INSERT INTO static_scan(file_path,file_name,file_type,md5,sha256,compile_time,publisher,pe_info,strings_info,rule_hits,risk_level,virus_name,conclusion,file_size) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    for (auto &s : statics) {
        q.bindValue(0,s.path); q.bindValue(1,s.name); q.bindValue(2,s.type);
        q.bindValue(3,s.md5);  q.bindValue(4,s.sha256); q.bindValue(5,s.compileTime);
        q.bindValue(6,s.publisher); q.bindValue(7,s.peInfo); q.bindValue(8,s.strings);
        q.bindValue(9,s.ruleHits); q.bindValue(10,s.risk); q.bindValue(11,s.virus);
        q.bindValue(12,s.conclusion); q.bindValue(13,s.size); q.exec();
    }

    // ── 15. 数字证书 ─────────────────────────────────────────────────────────
    struct CertRow { QString path,subject,issuer,serial,notBefore,notAfter,hashAlg,sha1,sha256,verify; int hasSig,valid,tampered,expired; };
    QList<CertRow> certs = {
        {"C:\\Windows\\Temp\\svchost32.exe","","","","","","","","","无数字签名",0,0,0,1},
        {"C:\\Windows\\Temp\\payload.dll","","","","","","","","","无数字签名",0,0,0,1},
        {"C:\\Program Files\\Google\\Chrome\\chrome.exe",
         "Google LLC","DigiCert SHA2 Assured ID Code Signing CA","03:1B:FC:A4:D8:3B:1E:F9:B2:C1:4D:A0:3D:A7:A2:4F",
         "2025-01-01","2026-01-01","SHA256","A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0",
         "1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2","签名有效，证书未过期",1,1,0,1},
        {"C:\\Users\\Administrator\\Desktop\\report.pdf.exe","","","","","","","","","无数字签名",0,0,0,1},
    };
    q.prepare("INSERT INTO cert_scan(file_path,has_signature,signature_valid,file_tampered,subject,issuer,serial_number,not_before,not_after,not_expired,hash_algorithm,thumbprint_sha1,thumbprint_sha256,verify_result) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    for (auto &c : certs) {
        q.bindValue(0,c.path); q.bindValue(1,c.hasSig); q.bindValue(2,c.valid);
        q.bindValue(3,c.tampered); q.bindValue(4,c.subject); q.bindValue(5,c.issuer);
        q.bindValue(6,c.serial); q.bindValue(7,c.notBefore); q.bindValue(8,c.notAfter);
        q.bindValue(9,c.expired); q.bindValue(10,c.hashAlg); q.bindValue(11,c.sha1);
        q.bindValue(12,c.sha256); q.bindValue(13,c.verify); q.exec();
    }

    // ── 16. 动态行为检测 ─────────────────────────────────────────────────────
    struct DynRow { QString path,btype,atype,src,target,detail,risk; int ppid,pid; };
    QList<DynRow> dyns = {
        {"C:\\Windows\\Temp\\svchost32.exe","registry","write","svchost32.exe",
         "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate",
         "写入注册表自启动项","high",0,9012},
        {"C:\\Windows\\Temp\\svchost32.exe","registry","write","svchost32.exe",
         "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MalSvc",
         "创建系统服务注册表项","high",0,9012},
        {"C:\\Windows\\Temp\\svchost32.exe","file","create","svchost32.exe",
         "C:\\Windows\\Temp\\payload.dll","释放恶意DLL文件","high",0,9012},
        {"C:\\Windows\\Temp\\svchost32.exe","file","modify","svchost32.exe",
         "C:\\Windows\\System32\\hosts","修改hosts文件","medium",0,9012},
        {"C:\\Windows\\Temp\\svchost32.exe","process","inject","svchost32.exe",
         "explorer.exe","注入explorer.exe进程","high",9012,1234},
        {"C:\\Windows\\Temp\\svchost32.exe","process","create","svchost32.exe",
         "cmd.exe","创建子进程执行命令","medium",9012,8888},
        {"C:\\Windows\\Temp\\svchost32.exe","network","connect","svchost32.exe",
         "185.220.101.5:4444","连接可疑C2服务器","high",0,9012},
        {"C:\\Windows\\Temp\\svchost32.exe","network","dns","svchost32.exe",
         "evil-c2.example.com","解析可疑域名","medium",0,9012},
        {"C:\\Windows\\Temp\\svchost32.exe","ssdt","hook","svchost32.exe",
         "NtCreateFile","SSDT钩子拦截文件创建","high",0,9012},
        {"C:\\Windows\\Temp\\svchost32.exe","autorun","add","svchost32.exe",
         "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Update",
         "添加用户级自启动项","high",0,9012},
        {"C:\\Windows\\Temp\\svchost32.exe","task","create","svchost32.exe",
         "\\Microsoft\\Windows\\MalwareTask","创建计划任务实现持久化","high",0,9012},
        {"C:\\Windows\\Temp\\svchost32.exe","browser","modify","svchost32.exe",
         "Chrome扩展目录","安装恶意浏览器扩展","medium",0,9012},
    };
    q.prepare("INSERT INTO dynamic_scan(sample_path,behavior_type,action_type,source_proc,target_path,detail,risk_level,parent_pid,pid) VALUES(?,?,?,?,?,?,?,?,?)");
    for (auto &d : dyns) {
        q.bindValue(0,d.path); q.bindValue(1,d.btype); q.bindValue(2,d.atype);
        q.bindValue(3,d.src); q.bindValue(4,d.target); q.bindValue(5,d.detail);
        q.bindValue(6,d.risk); q.bindValue(7,d.ppid); q.bindValue(8,d.pid); q.exec();
    }

    // ── 17. 文件关联检测 ─────────────────────────────────────────────────────
    struct AssocRow { QString ext,type,orig,curr,risk; };
    QList<AssocRow> assocs = {
        {".exe","open","C:\\Windows\\System32\\cmd.exe","C:\\Windows\\System32\\cmd.exe","clean"},
        {".pdf","open","C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
         "C:\\Windows\\Temp\\svchost32.exe \"%1\"","high"},
        {".doc","open","C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
         "C:\\Windows\\Temp\\payload.dll,OpenDoc \"%1\"","high"},
        {".txt","open","C:\\Windows\\System32\\notepad.exe","C:\\Windows\\System32\\notepad.exe","clean"},
        {".zip","open","C:\\Program Files\\WinRAR\\WinRAR.exe",
         "C:\\Windows\\Temp\\wuauclt32.exe \"%1\"","medium"},
        {".jpg","open","C:\\Windows\\System32\\mspaint.exe","C:\\Windows\\System32\\mspaint.exe","clean"},
    };
    q.prepare("INSERT INTO file_assoc_scan(ext,assoc_type,original_cmd,current_cmd,risk_level) VALUES(?,?,?,?,?)");
    for (auto &a : assocs) {
        q.bindValue(0,a.ext); q.bindValue(1,a.type); q.bindValue(2,a.orig);
        q.bindValue(3,a.curr); q.bindValue(4,a.risk); q.exec();
    }

    // ── 18. 样本提取 ─────────────────────────────────────────────────────────
    struct SampleRow { QString src,type,dst,md5,sha256,mtime,ctime,note; };
    QList<SampleRow> samples = {
        {"C:\\Windows\\Temp\\svchost32.exe","static",
         "C:\\Reports\\Samples\\svchost32_static.bin",
         "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
         "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b",
         "2025-11-20 02:13:44","2025-11-20 02:13:44","静态检测样本，保留原始时间属性"},
        {"C:\\Windows\\Temp\\payload.dll","static",
         "C:\\Reports\\Samples\\payload_static.bin",
         "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
         "4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c",
         "2025-11-18 15:22:33","2025-11-18 15:22:33","静态检测样本"},
        {"C:\\Windows\\Temp\\svchost32.exe","dynamic",
         "C:\\Reports\\Samples\\svchost32_dynamic.bin",
         "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
         "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b",
         "2025-11-20 02:13:44","2025-11-20 02:13:44","动态行为检测样本，含行为特征"},
        {"C:\\Users\\Administrator\\Desktop\\report.pdf.exe","static",
         "C:\\Reports\\Samples\\report_pdf_exe_static.bin",
         "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
         "6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e",
         "2025-11-15 09:30:00","2025-11-15 09:30:00","伪装PDF样本"},
    };
    q.prepare("INSERT INTO sample_extract(source_path,extract_type,sample_path,md5,sha256,original_mtime,original_ctime,note) VALUES(?,?,?,?,?,?,?,?)");
    for (auto &s : samples) {
        q.bindValue(0,s.src); q.bindValue(1,s.type); q.bindValue(2,s.dst);
        q.bindValue(3,s.md5); q.bindValue(4,s.sha256); q.bindValue(5,s.mtime);
        q.bindValue(6,s.ctime); q.bindValue(7,s.note); q.exec();
    }

    // ── 19. 日志审计 ─────────────────────────────────────────────────────────
    struct LogRow { QString role,user,action,detail,result,ip,ts; };
    QList<LogRow> logs = {
        {"system_admin","admin","登录","用户登录系统","success","192.168.1.100","2025-11-20 09:41:23"},
        {"sec_admin","secadmin","登录","用户登录系统","success","192.168.1.101","2025-11-20 09:42:05"},
        {"sec_admin","secadmin","扫描","发起静态检测：svchost32.exe","success","192.168.1.101","2025-11-20 09:43:11"},
        {"sec_admin","secadmin","扫描","发起动态行为检测","success","192.168.1.101","2025-11-20 09:44:30"},
        {"sec_admin","secadmin","报告","生成检测报告","success","192.168.1.101","2025-11-20 09:50:17"},
        {"sec_admin","secadmin","导出","导出HTML报告","success","192.168.1.101","2025-11-20 09:51:02"},
        {"auditor","auditor","登录","用户登录系统","success","192.168.1.102","2025-11-20 10:00:00"},
        {"auditor","auditor","日志查询","查询操作日志","success","192.168.1.102","2025-11-20 10:01:15"},
        {"system_admin","admin","设置","更新病毒库至20251120","success","192.168.1.100","2025-11-20 10:05:00"},
        {"system_admin","admin","白名单","添加白名单路径","success","192.168.1.100","2025-11-20 10:10:00"},
        {"sec_admin","secadmin","登录","用户登录系统","failed","192.168.1.101","2025-11-19 08:30:00"},
        {"sec_admin","secadmin","登录","用户登录系统（重试）","success","192.168.1.101","2025-11-19 08:31:00"},
    };
    q.prepare("INSERT INTO audit_log(role,username,action,detail,result,ip_address,timestamp) VALUES(?,?,?,?,?,?,?)");
    for (auto &l : logs) {
        q.bindValue(0,l.role); q.bindValue(1,l.user); q.bindValue(2,l.action);
        q.bindValue(3,l.detail); q.bindValue(4,l.result); q.bindValue(5,l.ip);
        q.bindValue(6,l.ts); q.exec();
    }

    // ── 20. 用户管理 ─────────────────────────────────────────────────────────
    struct UserRow { QString name,role,status,lastLogin; };
    QList<UserRow> users = {
        {"admin",    "system_admin","active","2025-11-20 09:41:23"},
        {"secadmin", "sec_admin",   "active","2025-11-20 09:42:05"},
        {"auditor",  "auditor",     "active","2025-11-20 10:00:00"},
    };
    q.prepare("INSERT OR IGNORE INTO users(username,role,status,last_login) VALUES(?,?,?,?)");
    for (auto &u : users) {
        q.bindValue(0,u.name); q.bindValue(1,u.role);
        q.bindValue(2,u.status); q.bindValue(3,u.lastLogin); q.exec();
    }

    // ── 21. 白名单 ───────────────────────────────────────────────────────────
    struct WlRow { QString path,md5,note,addedBy; };
    QList<WlRow> wls = {
        {"C:\\Program Files\\Google\\Chrome\\chrome.exe",
         "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8","Google Chrome 浏览器","admin"},
        {"C:\\Windows\\System32\\notepad.exe",
         "","Windows 系统记事本","admin"},
        {"C:\\Program Files\\WinRAR\\WinRAR.exe",
         "","WinRAR 解压软件","admin"},
    };
    q.prepare("INSERT INTO whitelist(path,md5,note,added_by) VALUES(?,?,?,?)");
    for (auto &w : wls) {
        q.bindValue(0,w.path); q.bindValue(1,w.md5);
        q.bindValue(2,w.note); q.bindValue(3,w.addedBy); q.exec();
    }

    // ── 22. 自定义规则 ───────────────────────────────────────────────────────
    struct RuleRow { QString name,type,pattern,desc; int enabled; };
    QList<RuleRow> rules = {
        {"检测Temp目录可执行文件","路径规则","C:\\\\Windows\\\\Temp\\\\.*\\.exe","检测Windows Temp目录下的可执行文件",1},
        {"检测双扩展名文件","文件名规则",".*\\.pdf\\.exe|.*\\.doc\\.exe|.*\\.jpg\\.exe","检测伪装为文档的可执行文件",1},
        {"检测可疑C2地址","网络规则","185\\.220\\..*|194\\.165\\..*","检测连接Tor出口节点",1},
    };
    q.prepare("INSERT INTO custom_rules(name,rule_type,pattern,description,enabled) VALUES(?,?,?,?,?)");
    for (auto &r : rules) {
        q.bindValue(0,r.name); q.bindValue(1,r.type); q.bindValue(2,r.pattern);
        q.bindValue(3,r.desc); q.bindValue(4,r.enabled); q.exec();
    }
}

// ── 系统设置 ──────────────────────────────────────────────────────────────────

QString DatabaseManager::getSetting(const QString &key, const QString &defaultVal)
{
    auto row = execSelectOne("SELECT value FROM settings WHERE key=?", {key});
    return row.isEmpty() ? defaultVal : row["value"].toString();
}

bool DatabaseManager::setSetting(const QString &key, const QString &value)
{
    QSqlQuery q(m_db);
    q.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)");
    q.addBindValue(key); q.addBindValue(value);
    if (!q.exec()) { m_lastError = q.lastError().text(); return false; }
    return true;
}

// ── 日志审计 ──────────────────────────────────────────────────────────────────

bool DatabaseManager::writeLog(const QString &role, const QString &username,
                                const QString &action, const QString &detail,
                                const QString &result, const QString &ip)
{
    QSqlQuery q(m_db);
    q.prepare("INSERT INTO audit_log(role,username,action,detail,result,ip_address) VALUES(?,?,?,?,?,?)");
    q.addBindValue(role); q.addBindValue(username); q.addBindValue(action);
    q.addBindValue(detail); q.addBindValue(result); q.addBindValue(ip);
    if (!q.exec()) { m_lastError = q.lastError().text(); return false; }
    return true;
}

QList<LogRecord> DatabaseManager::queryLogs(const QString &role, const QString &type,
                                              const QString &username,
                                              const QDateTime &from, const QDateTime &to,
                                              int limit)
{
    QString sql = "SELECT * FROM audit_log WHERE 1=1";
    QVariantList binds;
    if (!role.isEmpty())     { sql += " AND role=?";      binds << role; }
    if (!type.isEmpty())     { sql += " AND action=?";    binds << type; }
    if (!username.isEmpty()) { sql += " AND username LIKE ?"; binds << "%" + username + "%"; }
    if (from.isValid())      { sql += " AND timestamp>=?"; binds << from.toString("yyyy-MM-dd hh:mm:ss"); }
    if (to.isValid())        { sql += " AND timestamp<=?"; binds << to.toString("yyyy-MM-dd hh:mm:ss"); }
    sql += " ORDER BY timestamp DESC LIMIT ?";
    binds << limit;

    QList<LogRecord> result;
    for (auto &row : execSelect(sql, binds)) {
        auto m = row.toMap();
        LogRecord r;
        r.id        = m["id"].toInt();
        r.role      = m["role"].toString();
        r.username  = m["username"].toString();
        r.action    = m["action"].toString();
        r.detail    = m["detail"].toString();
        r.result    = m["result"].toString();
        r.ip_address= m["ip_address"].toString();
        r.timestamp = QDateTime::fromString(m["timestamp"].toString(), "yyyy-MM-dd hh:mm:ss");
        result << r;
    }
    return result;
}

// ── 系统信息采集查询 ──────────────────────────────────────────────────────────

QVariantList DatabaseManager::querySysInfo()
{
    return execSelect("SELECT key,value FROM sys_info ORDER BY id");
}

QVariantList DatabaseManager::queryNetInfo()
{
    return execSelect("SELECT name,ip,mask,gateway,mac,status FROM net_info ORDER BY id");
}

QVariantList DatabaseManager::queryDiskInfo()
{
    return execSelect("SELECT drive,type,filesystem,total_gb,free_gb,used_pct,serial FROM disk_info ORDER BY id");
}

QVariantList DatabaseManager::queryProcessInfo()
{
    return execSelect("SELECT pid,name,path,user,cpu_pct,mem_mb,status,risk FROM process_info ORDER BY risk DESC, cpu_pct DESC");
}

QVariantList DatabaseManager::queryPortInfo()
{
    return execSelect("SELECT protocol,local_ip,local_port,remote_ip,remote_port,state,process_name,pid,risk FROM port_info ORDER BY risk DESC, id");
}

QVariantList DatabaseManager::queryAutorunInfo(const QString &type)
{
    if (type.isEmpty())
        return execSelect("SELECT * FROM autorun_info ORDER BY risk DESC, id");
    return execSelect("SELECT * FROM autorun_info WHERE type=? ORDER BY risk DESC, id", {type});
}

QVariantList DatabaseManager::queryScheduledTasks()
{
    return execSelect("SELECT name,path,trigger,action,status,last_run,risk FROM scheduled_task ORDER BY risk DESC, id");
}

QVariantList DatabaseManager::queryDriverInfo(const QString &typeFilter)
{
    if (typeFilter.isEmpty() || typeFilter == "全部类型")
        return execSelect("SELECT name,type,publisher,modified_time,path,is_signed,risk FROM driver_info ORDER BY risk DESC, id");
    return execSelect("SELECT name,type,publisher,modified_time,path,is_signed,risk FROM driver_info WHERE type=? ORDER BY risk DESC, id", {typeFilter});
}

QVariantList DatabaseManager::querySharedResources()
{
    return execSelect("SELECT name,path,type,permission,connected,risk FROM shared_resource ORDER BY risk DESC, id");
}

QVariantList DatabaseManager::queryBrowserPlugins(const QString &browser)
{
    if (browser.isEmpty() || browser == "全部浏览器")
        return execSelect("SELECT browser,name,version,publisher,status,risk FROM browser_plugin ORDER BY risk DESC, id");
    return execSelect("SELECT browser,name,version,publisher,status,risk FROM browser_plugin WHERE browser=? ORDER BY risk DESC, id", {browser});
}

QVariantMap DatabaseManager::queryMemoryStatus()
{
    return execSelectOne("SELECT total_mb,used_mb,avail_mb,virtual_mb,page_file FROM memory_status ORDER BY id DESC LIMIT 1");
}

QVariantList DatabaseManager::queryKernelModules()
{
    return execSelect("SELECT name,base_address,image_size,flags,idx,path,is_trusted FROM kernel_module ORDER BY idx");
}

QVariantList DatabaseManager::queryProcessMemory()
{
    return execSelect("SELECT name,pid,private_mb,working_set_mb,virtual_mb,suspicious_inject FROM process_memory ORDER BY private_mb DESC");
}

// ── 静态检测查询 ──────────────────────────────────────────────────────────────

QVariantList DatabaseManager::queryStaticScanFiles()
{
    return execSelect("SELECT id,file_name,file_size,file_type,risk_level,scan_time FROM static_scan ORDER BY id");
}

QVariantMap DatabaseManager::queryStaticScanDetail(int id)
{
    return execSelectOne("SELECT * FROM static_scan WHERE id=?", {id});
}

QVariantList DatabaseManager::queryStaticScanStrings(int id)
{
    auto row = execSelectOne("SELECT strings_info FROM static_scan WHERE id=?", {id});
    if (row.isEmpty()) return {};
    QJsonDocument doc = QJsonDocument::fromJson(row["strings_info"].toString().toUtf8());
    QVariantList result;
    for (auto v : doc.array()) result << v.toString();
    return result;
}

QVariantList DatabaseManager::queryStaticScanRuleHits(int id)
{
    auto row = execSelectOne("SELECT rule_hits FROM static_scan WHERE id=?", {id});
    if (row.isEmpty()) return {};
    QJsonDocument doc = QJsonDocument::fromJson(row["rule_hits"].toString().toUtf8());
    QVariantList result;
    for (auto v : doc.array()) result << v.toVariant();
    return result;
}

QVariantMap DatabaseManager::queryStaticScanCert(int id)
{
    auto fileRow = execSelectOne("SELECT file_path FROM static_scan WHERE id=?", {id});
    if (fileRow.isEmpty()) return {};
    return execSelectOne("SELECT * FROM cert_scan WHERE file_path=? ORDER BY id DESC LIMIT 1",
                         {fileRow["file_path"].toString()});
}

// ── 动态行为检测查询 ──────────────────────────────────────────────────────────

QVariantList DatabaseManager::queryDynamicScan(const QString &behaviorType)
{
    if (behaviorType.isEmpty())
        return execSelect("SELECT * FROM dynamic_scan ORDER BY risk_level DESC, id");
    return execSelect("SELECT * FROM dynamic_scan WHERE behavior_type=? ORDER BY risk_level DESC, id",
                      {behaviorType});
}

QVariantList DatabaseManager::queryProcessTree()
{
    return execSelect("SELECT source_proc,pid,parent_pid,target_path,detail,risk_level FROM dynamic_scan WHERE behavior_type='process' ORDER BY parent_pid, pid");
}

// ── 文件关联检测查询 ──────────────────────────────────────────────────────────

QVariantList DatabaseManager::queryFileAssoc()
{
    return execSelect("SELECT ext,assoc_type,original_cmd,current_cmd,risk_level FROM file_assoc_scan ORDER BY risk_level DESC, id");
}

// ── 样本提取查询 ──────────────────────────────────────────────────────────────

QVariantList DatabaseManager::querySampleExtract()
{
    return execSelect("SELECT id,source_path,extract_type,sample_path,md5,sha256,original_mtime,original_ctime,note,extract_time FROM sample_extract ORDER BY id");
}

// ── 检测报告汇总 ──────────────────────────────────────────────────────────────

QVariantMap DatabaseManager::queryReportSummary()
{
    QVariantMap result;
    auto r1 = execSelectOne("SELECT COUNT(*) as cnt FROM static_scan WHERE risk_level='high'");
    auto r2 = execSelectOne("SELECT COUNT(*) as cnt FROM static_scan WHERE risk_level='medium'");
    auto r3 = execSelectOne("SELECT COUNT(*) as cnt FROM static_scan WHERE risk_level='low'");
    auto r4 = execSelectOne("SELECT COUNT(*) as cnt FROM dynamic_scan WHERE risk_level='high'");
    result["static_high"]   = r1["cnt"].toInt();
    result["static_medium"] = r2["cnt"].toInt();
    result["static_low"]    = r3["cnt"].toInt();
    result["dynamic_high"]  = r4["cnt"].toInt();
    result["total_high"]    = r1["cnt"].toInt() + r4["cnt"].toInt();
    return result;
}

QVariantList DatabaseManager::queryReportThreats()
{
    return execSelect(
        "SELECT file_name as name, risk_level, 'malware' as type, file_path as path, scan_time as found_time, '待处置' as status "
        "FROM static_scan WHERE risk_level IN ('high','medium') "
        "ORDER BY risk_level DESC, scan_time DESC");
}

// ── Dashboard 查询 ────────────────────────────────────────────────────────────

QVariantMap DatabaseManager::queryDashboardStats()
{
    QVariantMap result;
    auto r1 = execSelectOne("SELECT COUNT(*) as cnt FROM static_scan WHERE risk_level='high'");
    auto r2 = execSelectOne("SELECT COUNT(*) as cnt FROM static_scan WHERE risk_level='medium'");
    auto r3 = execSelectOne("SELECT COUNT(*) as cnt FROM static_scan WHERE risk_level='low' OR risk_level='clean'");
    result["high"]       = r1["cnt"].toInt();
    result["medium"]     = r2["cnt"].toInt();
    result["low"]        = r3["cnt"].toInt();
    result["protect_days"] = 127;
    result["db_version"] = getSetting("virus_db_version", "20251120");
    result["os"]         = execSelectOne("SELECT value FROM sys_info WHERE key='操作系统'")["value"].toString();
    result["hostname"]   = execSelectOne("SELECT value FROM sys_info WHERE key='计算机名称'")["value"].toString();
    result["version"]    = getSetting("product_version", "V3.0.20251120");
    return result;
}

QVariantList DatabaseManager::queryRecentAlerts(int limit)
{
    return execSelect(
        "SELECT file_name as name, risk_level, scan_time as time, '待处置' as status "
        "FROM static_scan WHERE risk_level IN ('high','medium') "
        "ORDER BY scan_time DESC LIMIT ?", {limit});
}
