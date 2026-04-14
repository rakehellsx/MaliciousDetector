#include "DatabaseManager.h"
#include <QStandardPaths>
#include <QDir>
#include <QDebug>
#include <QSqlRecord>
#include <QVariant>

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

bool DatabaseManager::createTables()
{
    QSqlQuery q(m_db);

    // 1. 系统信息采集结果表（basic.dll 各模块结果，统一存储）
    q.exec(R"(
        CREATE TABLE IF NOT EXISTS detection_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            module_name TEXT    NOT NULL,
            params_json TEXT,
            result_json TEXT,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
        )
    )");

    // 2. 静态检测结果表
    q.exec(R"(
        CREATE TABLE IF NOT EXISTS static_scan (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path    TEXT NOT NULL,
            file_name    TEXT,
            file_size    INTEGER,
            file_type    TEXT,
            md5          TEXT,
            sha1         TEXT,
            sha256       TEXT,
            pe_info      TEXT,       -- JSON: PE结构信息
            strings_info TEXT,       -- JSON: 提取的字符串
            rule_hits    TEXT,       -- JSON: 规则命中列表
            risk_level   TEXT,       -- high/medium/low/clean
            virus_name   TEXT,       -- 病毒名称（安全时为空，威胁时填写具体病毒名）
            conclusion   TEXT,       -- 检测结论
            scan_time    TEXT        NOT NULL DEFAULT (datetime('now','localtime'))
        )
    ");
    // 兼容旧数据库：若 virus_name 字段不存在则添加
    q.exec("ALTER TABLE static_scan ADD COLUMN virus_name TEXT");

    // 3. 动态行为检测结果表
    q.exec(R"(
        CREATE TABLE IF NOT EXISTS dynamic_scan (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sample_path  TEXT NOT NULL,
            behavior_type TEXT NOT NULL,  -- registry/file/process/network/ssdt/autorun/task/browser
            action_type  TEXT,
            source_proc  TEXT,
            target_path  TEXT,
            detail       TEXT,
            risk_level   TEXT,
            scan_time    TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    )");

    // 4. 数字证书检测结果表
    q.exec(R"(
        CREATE TABLE IF NOT EXISTS cert_scan (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path        TEXT NOT NULL,
            has_signature    INTEGER,
            signature_valid  INTEGER,
            file_tampered    INTEGER,
            subject          TEXT,
            issuer           TEXT,
            serial_number    TEXT,
            not_before       TEXT,
            not_after        TEXT,
            not_expired      INTEGER,
            hash_algorithm   TEXT,
            thumbprint_sha1  TEXT,
            thumbprint_sha256 TEXT,
            verify_result    TEXT,
            full_result_json TEXT,
            scan_time        TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    )");

    // 5. 文件关联检测结果表
    q.exec(R"(
        CREATE TABLE IF NOT EXISTS file_assoc_scan (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ext          TEXT,
            assoc_type   TEXT,   -- open/hijack/modified
            original_cmd TEXT,
            current_cmd  TEXT,
            risk_level   TEXT,
            scan_time    TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    )");

    // 6. 样本提取记录表
    q.exec(R"(
        CREATE TABLE IF NOT EXISTS sample_extract (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            source_path  TEXT NOT NULL,
            extract_type TEXT,   -- static/dynamic
            sample_path  TEXT,
            md5          TEXT,
            sha256       TEXT,
            original_mtime TEXT,
            original_ctime TEXT,
            note         TEXT,
            extract_time TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    )");

    // 7. 操作日志审计表
    q.exec(R"(
        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            role      TEXT NOT NULL,
            username  TEXT NOT NULL,
            action    TEXT NOT NULL,
            detail    TEXT,
            result    TEXT DEFAULT 'success',
            timestamp TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    )");

    // 8. 系统设置表
    q.exec(R"(
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
    )");

    // 初始化默认设置
    QSqlQuery sq(m_db);
    sq.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)");
    QList<QPair<QString,QString>> defaults = {
        {"dll_path",        "basic.dll"},
        {"db_path",         ""},
        {"virus_db_version","20251120"},
        {"auto_scan",       "false"},
        {"scan_on_startup", "false"},
        {"realtime_protect","false"},
        {"log_retention_days","90"},
        {"report_output_dir","./reports"},
        {"whitelist",       "[]"},
        {"custom_rules",    "[]"},
    };
    for (auto &kv : defaults) {
        sq.bindValue(0, kv.first);
        sq.bindValue(1, kv.second);
        sq.exec();
    }

    if (q.lastError().isValid()) {
        m_lastError = q.lastError().text();
        return false;
    }
    // 如果是第一次初始化，插入测试数据
    QSqlQuery chk(m_db);
    chk.exec("SELECT COUNT(*) FROM detection_results");
    if (chk.next() && chk.value(0).toInt() == 0) {
        insertTestData();
    }
    return true;
}

// ── 日志操作 ─────────────────────────────────────────────────────────────

bool DatabaseManager::writeLog(const QString &role, const QString &username,
                                const QString &action, const QString &detail,
                                const QString &result)
{
    QSqlQuery q(m_db);
    q.prepare("INSERT INTO audit_log(role,username,action,detail,result) VALUES(?,?,?,?,?)");
    q.addBindValue(role);
    q.addBindValue(username);
    q.addBindValue(action);
    q.addBindValue(detail);
    q.addBindValue(result);
    if (!q.exec()) {
        m_lastError = q.lastError().text();
        return false;
    }
    return true;
}

QList<LogRecord> DatabaseManager::queryLogs(const QString &role,
                                              const QDateTime &from,
                                              const QDateTime &to,
                                              int limit)
{
    QList<LogRecord> list;
    QString sql = "SELECT id,role,username,action,detail,result,timestamp FROM audit_log WHERE 1=1";
    if (!role.isEmpty())  sql += " AND role=:role";
    if (from.isValid())   sql += " AND timestamp>=:from";
    if (to.isValid())     sql += " AND timestamp<=:to";
    sql += " ORDER BY id DESC LIMIT :limit";

    QSqlQuery q(m_db);
    q.prepare(sql);
    if (!role.isEmpty())  q.bindValue(":role", role);
    if (from.isValid())   q.bindValue(":from", from.toString("yyyy-MM-dd HH:mm:ss"));
    if (to.isValid())     q.bindValue(":to",   to.toString("yyyy-MM-dd HH:mm:ss"));
    q.bindValue(":limit", limit);
    q.exec();

    while (q.next()) {
        LogRecord r;
        r.id        = q.value(0).toInt();
        r.role      = q.value(1).toString();
        r.username  = q.value(2).toString();
        r.action    = q.value(3).toString();
        r.detail    = q.value(4).toString();
        r.result    = q.value(5).toString();
        r.timestamp = QDateTime::fromString(q.value(6).toString(), "yyyy-MM-dd HH:mm:ss");
        list.append(r);
    }
    return list;
}

// ── 扫描结果操作 ─────────────────────────────────────────────────────────

bool DatabaseManager::saveScanResult(const QString &moduleName,
                                      const QString &paramsJson,
                                      const QString &resultJson)
{
    QSqlQuery q(m_db);
    q.prepare("INSERT INTO detection_results(module_name,params_json,result_json) VALUES(?,?,?)");
    q.addBindValue(moduleName);
    q.addBindValue(paramsJson);
    q.addBindValue(resultJson);
    if (!q.exec()) {
        m_lastError = q.lastError().text();
        return false;
    }
    return true;
}

QList<ScanRecord> DatabaseManager::queryScanHistory(const QString &moduleName, int limit)
{
    QList<ScanRecord> list;
    QString sql = "SELECT id,module_name,params_json,result_json,created_at FROM detection_results";
    if (!moduleName.isEmpty()) sql += " WHERE module_name=:mod";
    sql += " ORDER BY id DESC LIMIT :limit";

    QSqlQuery q(m_db);
    q.prepare(sql);
    if (!moduleName.isEmpty()) q.bindValue(":mod", moduleName);
    q.bindValue(":limit", limit);
    q.exec();

    while (q.next()) {
        ScanRecord r;
        r.id         = q.value(0).toInt();
        r.moduleName = q.value(1).toString();
        r.paramsJson = q.value(2).toString();
        r.resultJson = q.value(3).toString();
        r.createdAt  = QDateTime::fromString(q.value(4).toString(), "yyyy-MM-dd HH:mm:ss");
        list.append(r);
    }
    return list;
}

// ── 系统设置 ─────────────────────────────────────────────────────────────

QString DatabaseManager::getSetting(const QString &key, const QString &defaultVal)
{
    QSqlQuery q(m_db);
    q.prepare("SELECT value FROM settings WHERE key=?");
    q.addBindValue(key);
    if (q.exec() && q.next()) return q.value(0).toString();
    return defaultVal;
}

bool DatabaseManager::setSetting(const QString &key, const QString &value)
{
    QSqlQuery q(m_db);
    q.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)");
    q.addBindValue(key);
    q.addBindValue(value);
    if (!q.exec()) { m_lastError = q.lastError().text(); return false; }
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// 测试数据初始化 - 覆盖所有功能模块，确保每个页面开箱即用
// ═══════════════════════════════════════════════════════════════════════════
void DatabaseManager::insertTestData()
{
    QSqlQuery q(m_db);

    // ── 1. 系统信息采集模块测试数据 (detection_results) ──────────────────
    struct ModuleData { QString name; QString params; QString result; };
    QList<ModuleData> modules = {
        // 系统基本信息
        {"system_info", "{}",
         R"({"hostname":"SECURE-PC-001","os":"Windows 10 专业版 22H2","os_version":"10.0.19045","arch":"x64","cpu":"Intel Core i7-10700 @ 2.90GHz","cpu_cores":8,"total_memory":16384,"free_memory":6240,"system_dir":"C:\\Windows\\System32","temp_dir":"C:\\Users\\admin\\AppData\\Local\\Temp","computer_name":"SECURE-PC-001","domain":"WORKGROUP","install_date":"2024-03-15","last_boot":"2025-11-20 08:30:12"})"},
        // 网络信息
        {"network_info", "{}",
         R"([{"adapter":"以太网","ip":"192.168.1.100","mask":"255.255.255.0","gateway":"192.168.1.1","mac":"00:1A:2B:3C:4D:5E","dns1":"114.114.114.114","dns2":"8.8.8.8","status":"已连接"},{"adapter":"本地回环","ip":"127.0.0.1","mask":"255.0.0.0","gateway":"","mac":"","dns1":"","dns2":"","status":"已连接"}])"},
        // 硬盘信息
        {"disk_info", "{}",
         R"([{"drive":"C:","label":"系统盘","fs":"NTFS","total":512000,"free":186320,"used":325680,"usage_pct":63.6},{"drive":"D:","label":"数据盘","fs":"NTFS","total":1024000,"free":712400,"used":311600,"usage_pct":30.4}])"},
        // 进程信息
        {"process_info", "{}",
         R"([{"pid":4,"name":"System","path":"","user":"SYSTEM","cpu":0.1,"mem":1024,"start_time":"2025-11-20 08:30:00","parent_pid":0},{"pid":688,"name":"svchost.exe","path":"C:\\Windows\\System32\\svchost.exe","user":"SYSTEM","cpu":0.2,"mem":8192,"start_time":"2025-11-20 08:30:15","parent_pid":4},{"pid":1024,"name":"explorer.exe","path":"C:\\Windows\\explorer.exe","user":"admin","cpu":0.5,"mem":65536,"start_time":"2025-11-20 08:31:00","parent_pid":688},{"pid":2048,"name":"chrome.exe","path":"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","user":"admin","cpu":2.1,"mem":204800,"start_time":"2025-11-20 09:15:30","parent_pid":1024},{"pid":3120,"name":"notepad.exe","path":"C:\\Windows\\System32\\notepad.exe","user":"admin","cpu":0.0,"mem":4096,"start_time":"2025-11-20 10:22:00","parent_pid":1024},{"pid":5432,"name":"suspicious.exe","path":"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe","user":"admin","cpu":15.3,"mem":32768,"start_time":"2025-11-20 11:05:00","parent_pid":1024},{"pid":7788,"name":"MalwareDetector.exe","path":"C:\\Tools\\MalwareDetector\\MalwareDetector.exe","user":"admin","cpu":0.8,"mem":28672,"start_time":"2025-11-20 11:30:00","parent_pid":1024}])"},
        // 端口信息
        {"port_info", "{}",
         R"([{"protocol":"TCP","local_addr":"0.0.0.0","local_port":80,"remote_addr":"","remote_port":0,"state":"LISTEN","pid":688,"process":"svchost.exe"},{"protocol":"TCP","local_addr":"0.0.0.0","local_port":443,"remote_addr":"","remote_port":0,"state":"LISTEN","pid":688,"process":"svchost.exe"},{"protocol":"TCP","local_addr":"192.168.1.100","local_port":52341,"remote_addr":"203.0.113.45","remote_port":4444,"state":"ESTABLISHED","pid":5432,"process":"suspicious.exe"},{"protocol":"TCP","local_addr":"192.168.1.100","local_port":49152,"remote_addr":"142.250.80.46","remote_port":443,"state":"ESTABLISHED","pid":2048,"process":"chrome.exe"},{"protocol":"UDP","local_addr":"0.0.0.0","local_port":5355,"remote_addr":"","remote_port":0,"state":"","pid":688,"process":"svchost.exe"},{"protocol":"TCP","local_addr":"127.0.0.1","local_port":3306,"remote_addr":"","remote_port":0,"state":"LISTEN","pid":1234,"process":"mysqld.exe"}])"},
        // 自启动项
        {"autorun_info", "{}",
         R"([{"name":"SecurityHealth","path":"C:\\Windows\\System32\\SecurityHealthSystray.exe","location":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","type":"registry","enabled":true,"risk":"low"},{"name":"OneDrive","path":"C:\\Users\\admin\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background","location":"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","type":"registry","enabled":true,"risk":"low"},{"name":"SuspiciousStartup","path":"C:\\Users\\admin\\AppData\\Roaming\\update.exe","location":"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","type":"registry","enabled":true,"risk":"high"},{"name":"Chrome","path":"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","location":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","type":"registry","enabled":false,"risk":"low"},{"name":"MalwareTask","path":"C:\\Windows\\Temp\\svch0st.exe","location":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce","type":"registry","enabled":true,"risk":"high"}])"},
        // 计划任务
        {"scheduled_task_info", "{}",
         R"([{"name":"MicrosoftEdgeUpdateTaskMachineCore","path":"\\Microsoft\\Edge\\MicrosoftEdgeUpdateTaskMachineCore","trigger":"每天 09:00","action":"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe /c","status":"就绪","last_run":"2025-11-20 09:00:01","next_run":"2025-11-21 09:00:00","risk":"low"},{"name":"WindowsDefenderCache","path":"\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance","trigger":"每天","action":"C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.2109.6-0\\MpCmdRun.exe","status":"就绪","last_run":"2025-11-20 08:45:00","next_run":"2025-11-21 08:45:00","risk":"low"},{"name":"SuspiciousUpdateTask","path":"\\SuspiciousUpdateTask","trigger":"每5分钟","action":"C:\\Users\\admin\\AppData\\Roaming\\update.exe -silent","status":"运行中","last_run":"2025-11-20 11:30:00","next_run":"2025-11-20 11:35:00","risk":"high"},{"name":"GoogleUpdateTaskMachineCore","path":"\\GoogleUpdate\\GoogleUpdateTaskMachineCore","trigger":"每天 10:00","action":"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c","status":"就绪","last_run":"2025-11-20 10:00:02","next_run":"2025-11-21 10:00:00","risk":"low"}])"},
        // 驱动信息
        {"driver_info", "{}",
         R"([{"name":"ntfs","display_name":"NTFS","path":"C:\\Windows\\System32\\drivers\\ntfs.sys","type":"文件系统驱动","status":"运行中","start_type":"系统启动","version":"10.0.19041.1","company":"Microsoft","risk":"low"},{"name":"tcpip","display_name":"TCP/IP协议驱动","path":"C:\\Windows\\System32\\drivers\\tcpip.sys","type":"内核驱动","status":"运行中","start_type":"系统启动","version":"10.0.19041.1","company":"Microsoft","risk":"low"},{"name":"RootKit_Driver","display_name":"System Performance Monitor","path":"C:\\Windows\\System32\\drivers\\perfmon32.sys","type":"内核驱动","status":"运行中","start_type":"自动","version":"1.0.0.1","company":"Unknown","risk":"high"},{"name":"WdFilter","display_name":"Microsoft antimalware file system filter driver","path":"C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.2109.6-0\\MpFilter.sys","type":"文件系统驱动","status":"运行中","start_type":"自动","version":"4.18.2109.6","company":"Microsoft","risk":"low"}])"},
        // 共享资源
        {"shared_resource_info", "{}",
         R"([{"name":"ADMIN$","path":"C:\\Windows","type":"磁盘","remark":"远程管理","max_users":0,"current_users":0,"permissions":"管理员","risk":"low"},{"name":"C$","path":"C:\\","type":"磁盘","remark":"默认共享","max_users":0,"current_users":0,"permissions":"管理员","risk":"low"},{"name":"IPC$","path":"","type":"IPC","remark":"远程IPC","max_users":0,"current_users":0,"permissions":"Everyone","risk":"medium"},{"name":"SharedDocs","path":"D:\\SharedDocs","type":"磁盘","remark":"文档共享","max_users":10,"current_users":2,"permissions":"Everyone","risk":"medium"}])"},
        // 浏览器插件
        {"browser_plugin_info", "{}",
         R"([{"browser":"Chrome","name":"Google Docs Offline","id":"ghbmnnjooekpmoecnnnilnnbdlolhkhi","version":"1.67.0","enabled":true,"path":"C:\\Users\\admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\ghbmnnjooekpmoecnnnilnnbdlolhkhi","risk":"low"},{"browser":"Chrome","name":"AdBlock","id":"gighmmpiobklfepjocnamgkkbiglidom","version":"5.0.2","enabled":true,"path":"C:\\Users\\admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\gighmmpiobklfepjocnamgkkbiglidom","risk":"low"},{"browser":"Chrome","name":"Unknown Extension","id":"abcdefghijklmnopqrstuvwxyz123456","version":"0.0.1","enabled":true,"path":"C:\\Users\\admin\\AppData\\Roaming\\Chrome\\Extensions\\abcdefghijklmnopqrstuvwxyz123456","risk":"high"},{"browser":"Edge","name":"Microsoft Editor","id":"gpaiobkfhnonedkhhfjpmhdalgeoebfa","version":"1.0.0","enabled":true,"path":"","risk":"low"}])"},
        // 内存映像
        {"memory_image_info", "{}",
         R"([{"pid":5432,"name":"suspicious.exe","base_addr":"0x00400000","size":4096,"type":"MEM_IMAGE","protect":"PAGE_EXECUTE_READ","state":"MEM_COMMIT","mapped_file":"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe","risk":"high"},{"pid":5432,"name":"suspicious.exe","base_addr":"0x10000000","size":8192,"type":"MEM_PRIVATE","protect":"PAGE_EXECUTE_READWRITE","state":"MEM_COMMIT","mapped_file":"","risk":"high"},{"pid":1024,"name":"explorer.exe","base_addr":"0x00400000","size":2048,"type":"MEM_IMAGE","protect":"PAGE_EXECUTE_READ","state":"MEM_COMMIT","mapped_file":"C:\\Windows\\explorer.exe","risk":"low"},{"pid":2048,"name":"chrome.exe","base_addr":"0x00400000","size":16384,"type":"MEM_IMAGE","protect":"PAGE_EXECUTE_READ","state":"MEM_COMMIT","mapped_file":"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","risk":"low"}])"},
    };

    q.prepare("INSERT INTO detection_results(module_name,params_json,result_json) VALUES(?,?,?)");
    for (auto &m : modules) {
        q.addBindValue(m.name);
        q.addBindValue(m.params);
        q.addBindValue(m.result);
        q.exec();
    }

    // ── 2. 静态检测结果测试数据 ──────────────────────────────────────────
    struct StaticData {
        QString path, name, type, md5, sha256, peInfo, stringsInfo, ruleHits;
        QString risk, virusName, conclusion;
        qint64 size;
    };
    QList<StaticData> statics = {
        // 1. 高危木马 - suspicious.exe
        {"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe",
         "suspicious.exe", "PE32 executable (GUI) Intel 80386",
         "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         // PE 结构
         "文件类型:    PE32 可执行文件 (GUI) Intel 80386\n"
         "入口点:      0x00401A30\n"
         "编译时间:    2025-10-01 12:00:00 UTC\n"
         "加壳器:      UPX 3.96\n"
         "节区数量:    3\n"
         "  .text    VSize:0xB000  RSize:0xB200  Entropy:7.80 [高熵，已加壳]\n"
         "  .data    VSize:0x2000  RSize:0x2000  Entropy:6.20\n"
         "  .rsrc    VSize:0x1000  RSize:0x1000  Entropy:3.10\n"
         "\n导入表:\n"
         "  kernel32.dll: CreateProcess, VirtualAlloc, WriteProcessMemory, CreateRemoteThread\n"
         "  ws2_32.dll:   connect, send, recv, WSAStartup\n"
         "  advapi32.dll: RegSetValueEx, RegOpenKeyEx\n",
         // 字符串提取
         "[可疑字符串]\n"
         "  cmd.exe /c net user hacker Admin@123 /add\n"
         "  C:\\Windows\\Temp\\svch0st.exe\n"
         "  203.0.113.45\n"
         "  SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
         "  CreateRemoteThread\n"
         "  VirtualAllocEx\n"
         "  WriteProcessMemory\n"
         "  WinExec\n",
         // 规则命中
         "[{\"rule\":\"Trojan.Win32.Backdoor.Generic\",\"match\":\"ws2_32!connect + CreateRemoteThread\",\"severity\":\"high\"},{\"rule\":\"Suspicious.UPX.Packed\",\"match\":\"UPX packer detected entropy 7.80\",\"severity\":\"medium\"},{\"rule\":\"Network.ReverseShell\",\"match\":\"hardcoded C2 IP 203.0.113.45:4444\",\"severity\":\"high\"},{\"rule\":\"Persistence.Registry.Run\",\"match\":\"writes to HKCU Run registry key\",\"severity\":\"high\"}]",
         "high", "Trojan.Win32.Backdoor.Generic",
         "检测结论：[高危] Trojan.Win32.Backdoor.Generic\n\n"
         "该文件具有明显的恶意行为特征：\n"
         "1. PE节区存在高熵区域，已经过UPX加壳处理；\n"
         "2. 导入了进程注入相关API（CreateRemoteThread、VirtualAllocEx）；\n"
         "3. 包含注册表自启动写入行为，具备持久化能力；\n"
         "4. 存在网络通信行为，确认C2地址 203.0.113.45:4444；\n"
         "5. 字符串中发现明文命令行（添加管理员账户）。\n\n"
         "建议：立即隔离该文件，阻止其执行，并进行进一步的动态行为分析。",
         102400},
        // 2. 中危伪装进程 - svch0st.exe
        {"C:\\Windows\\Temp\\svch0st.exe",
         "svch0st.exe", "PE32 executable (console) Intel 80386",
         "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
         "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
         "文件类型:    PE32 可执行文件 (Console) Intel 80386\n"
         "入口点:      0x00401000\n"
         "编译时间:    2025-11-01 08:00:00 UTC\n"
         "加壳器:      无\n"
         "节区数量:    2\n"
         "  .text    VSize:0x5000  RSize:0x5200  Entropy:6.50\n"
         "  .data    VSize:0x1000  RSize:0x0200  Entropy:2.10\n"
         "\n导入表:\n"
         "  kernel32.dll: CreateProcess, OpenProcess, TerminateProcess\n"
         "  advapi32.dll: RegSetValueEx, RegOpenKeyEx, OpenSCManager\n",
         "[可疑字符串]\n"
         "  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
         "  C:\\Windows\\Temp\\svch0st.exe\n"
         "  svchost.exe  [注意：此处为伪装名称]\n"
         "  OpenSCManager\n"
         "  CreateService\n",
         "[{\"rule\":\"Suspicious.FakeSystemProcess\",\"match\":\"filename mimics svchost.exe (svch0st)\",\"severity\":\"medium\"},{\"rule\":\"Persistence.Autorun\",\"match\":\"writes to HKLM Run registry key\",\"severity\":\"high\"},{\"rule\":\"Suspicious.TempDirectory\",\"match\":\"executable located in TEMP\",\"severity\":\"medium\"}]",
         "medium", "Trojan.Win32.FakeProcess.Svchost",
         "检测结论：[中危] Trojan.Win32.FakeProcess.Svchost\n\n"
         "文件名伪装系统进程 svchost.exe（将字母 o 替换为数字 0），\n"
         "位于系统临时目录，存在注册表持久化行为。\n"
         "建议进一步动态分析。",
         49152},
        // 3. 安全 - chrome.exe
        {"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
         "chrome.exe", "PE32+ executable (GUI) x86-64",
         "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
         "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
         "文件类型:    PE32+ 可执行文件 (GUI) x86-64\n"
         "入口点:      0x0000000140001000\n"
         "编译时间:    2025-09-15 00:00:00 UTC\n"
         "加壳器:      无\n"
         "节区数量:    6\n"
         "  .text    VSize:0xA00000  Entropy:6.10\n"
         "  .rdata   VSize:0x500000  Entropy:5.80\n"
         "  .data    VSize:0x100000  Entropy:4.20\n"
         "\n导入表:\n"
         "  kernel32.dll: 常规系统调用\n"
         "  user32.dll:   常规UI调用\n"
         "  gdi32.dll:    常规绘图调用\n",
         "[字符串提取]无可疑内容",
         "[]",
         "clean", "",
         "检测结论：[安全] 未发现威胁\n\n"
         "该文件为合法的 Google Chrome 浏览器可执行文件，\n"
         "数字签名有效，文件未被篹改，未发现任何威胁。",
         10485760},
        // 4. 高危伪装PDF - invoice_2025.pdf.exe
        {"C:\\Users\\admin\\Desktop\\invoice_2025.pdf.exe",
         "invoice_2025.pdf.exe", "PE32 executable (GUI) Intel 80386",
         "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
         "b3a8e0e1f9ab1827e1311d14c6baad0b3f7b2a9e5c6d7e8f9a0b1c2d3e4f5a6",
         "文件类型:    PE32 可执行文件 (GUI) Intel 80386\n"
         "入口点:      0x00401000\n"
         "编译时间:    2025-11-18 14:30:00 UTC\n"
         "加壳器:      MPRESS 2.19\n"
         "节区数量:    2\n"
         "  .text    VSize:0x2000  RSize:0x2200  Entropy:7.90 [高熵，已加壳]\n"
         "  .rsrc    VSize:0x1000  RSize:0x1000  Entropy:3.50\n"
         "\n导入表:\n"
         "  kernel32.dll: CreateProcess, WinExec, ShellExecute\n"
         "  shell32.dll:  ShellExecuteEx\n"
         "\n[警告] 双扩展名伪装：.pdf.exe",
         "[可疑字符串]\n"
         "  .pdf.exe  [双扩展名伪装]\n"
         "  C:\\Users\\admin\\AppData\\Roaming\\malware.exe\n"
         "  http://evil-c2.example.com/payload\n"
         "  WinExec\n"
         "  ShellExecuteEx\n",
         "[{\"rule\":\"Trojan.Disguise.DoubleExtension\",\"match\":\"filename .pdf.exe double extension trick\",\"severity\":\"high\"},{\"rule\":\"Suspicious.HighEntropy.MPRESS\",\"match\":\"MPRESS packer section entropy 7.90\",\"severity\":\"medium\"},{\"rule\":\"Dropper.Generic\",\"match\":\"drops and executes secondary payload\",\"severity\":\"high\"}]",
         "high", "Trojan.Win32.Dropper.DoubleExtension",
         "检测结论：[高危] Trojan.Win32.Dropper.DoubleExtension\n\n"
         "该文件使用双扩展名(.pdf.exe)伪装PDF文档，\n"
         "经 MPRESS 加壳，节区熵値达 7.90，具有释放器特征。\n"
         "建议立即删除该文件并检查其来源。",
         24576},
    };

    q.prepare("INSERT INTO static_scan(file_path,file_name,file_size,file_type,md5,sha256,"
              "pe_info,strings_info,rule_hits,risk_level,virus_name,conclusion) "
              "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)");
    for (auto &s : statics) {
        q.addBindValue(s.path);       q.addBindValue(s.name);
        q.addBindValue(s.size);
        q.addBindValue(s.type);       q.addBindValue(s.md5);    q.addBindValue(s.sha256);
        q.addBindValue(s.peInfo);     q.addBindValue(s.stringsInfo);
        q.addBindValue(s.ruleHits);   q.addBindValue(s.risk);
        q.addBindValue(s.virusName);  q.addBindValue(s.conclusion);
        q.exec();
    }

    // ── 3. 动态行为检测测试数据 ──────────────────────────────────────────
    struct DynData { QString sample, btype, action, proc, target, detail, risk; };
    QList<DynData> dyns = {
        {"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe","registry","write","suspicious.exe",
         "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdate",
         "写入自启动注册表项，值：C:\\Users\\admin\\AppData\\Roaming\\update.exe","high"},
        {"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe","file","create","suspicious.exe",
         "C:\\Windows\\Temp\\svch0st.exe","释放子文件到系统临时目录","high"},
        {"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe","network","connect","suspicious.exe",
         "203.0.113.45:4444","建立反向Shell连接至C&C服务器","high"},
        {"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe","process","create","suspicious.exe",
         "cmd.exe /c whoami","通过cmd.exe执行系统命令","high"},
        {"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe","ssdt","hook","suspicious.exe",
         "NtOpenProcess","Hook系统调用NtOpenProcess，疑似Rootkit行为","high"},
        {"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe","autorun","write","suspicious.exe",
         "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
         "修改Winlogon Userinit实现持久化","high"},
        {"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe","task","create","suspicious.exe",
         "\\SuspiciousUpdateTask","创建计划任务每5分钟执行一次","medium"},
        {"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe","browser","modify","suspicious.exe",
         "Chrome扩展目录","向Chrome写入恶意扩展","medium"},
        {"C:\\Windows\\Temp\\svch0st.exe","registry","read","svch0st.exe",
         "HKLM\\SYSTEM\\CurrentControlSet\\Services","枚举系统服务","medium"},
        {"C:\\Windows\\Temp\\svch0st.exe","file","delete","svch0st.exe",
         "C:\\Windows\\Temp\\install.log","删除安装日志消除痕迹","medium"},
        {"C:\\Users\\admin\\Desktop\\invoice_2025.pdf.exe","process","inject","invoice_2025.pdf.exe",
         "explorer.exe (PID:1024)","进程注入到explorer.exe","high"},
        {"C:\\Users\\admin\\Desktop\\invoice_2025.pdf.exe","network","dns","invoice_2025.pdf.exe",
         "evil-c2.example.com","DNS查询C&C域名","high"},
    };

    q.prepare("INSERT INTO dynamic_scan(sample_path,behavior_type,action_type,source_proc,target_path,detail,risk_level) VALUES(?,?,?,?,?,?,?)");
    for (auto &d : dyns) {
        q.addBindValue(d.sample); q.addBindValue(d.btype); q.addBindValue(d.action);
        q.addBindValue(d.proc);   q.addBindValue(d.target); q.addBindValue(d.detail);
        q.addBindValue(d.risk);   q.exec();
    }

    // ── 4. 数字证书检测测试数据 ──────────────────────────────────────────
    struct CertData {
        QString path, subject, issuer, serial, notBefore, notAfter;
        int hasSig, sigValid, tampered, notExpired;
        QString hashAlg, thumbSha1, verifyResult;
    };
    QList<CertData> certs = {
        {"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
         "CN=Google LLC, O=Google LLC, L=Mountain View, ST=California, C=US",
         "CN=DigiCert SHA2 Assured ID Code Signing CA, O=DigiCert Inc, C=US",
         "0A:1B:2C:3D:4E:5F:6A:7B:8C:9D:0E:1F:2A:3B:4C:5D",
         "2025-01-01","2026-01-01",1,1,0,1,"SHA256",
         "A1:B2:C3:D4:E5:F6:A1:B2:C3:D4:E5:F6:A1:B2:C3:D4:E5:F6:A1:B2","验证通过"},
        {"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe",
         "","","",
         "","",0,0,0,0,"","","无数字签名"},
        {"C:\\Windows\\Temp\\svch0st.exe",
         "CN=Microsoft Windows, O=Microsoft Corporation, C=US",
         "CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, C=US",
         "33:00:00:01:2A:3B:4C:5D:6E:7F:8A:9B:0C:1D:2E:3F",
         "2020-01-01","2022-01-01",1,0,1,0,"SHA256",
         "B2:C3:D4:E5:F6:A1:B2:C3:D4:E5:F6:A1:B2:C3:D4:E5:F6:A1:B2:C3","签名已过期且文件被篡改"},
        {"C:\\Windows\\System32\\ntdll.dll",
         "CN=Microsoft Windows, O=Microsoft Corporation, C=US",
         "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, C=US",
         "33:00:00:01:9A:8B:7C:6D:5E:4F:3A:2B:1C:0D:9E:8F",
         "2025-06-01","2026-06-01",1,1,0,1,"SHA256",
         "C3:D4:E5:F6:A1:B2:C3:D4:E5:F6:A1:B2:C3:D4:E5:F6:A1:B2:C3:D4","验证通过"},
    };

    q.prepare("INSERT INTO cert_scan(file_path,has_signature,signature_valid,file_tampered,subject,issuer,serial_number,not_before,not_after,not_expired,hash_algorithm,thumbprint_sha1,verify_result) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)");
    for (auto &c : certs) {
        q.addBindValue(c.path);    q.addBindValue(c.hasSig);   q.addBindValue(c.sigValid);
        q.addBindValue(c.tampered);q.addBindValue(c.subject);  q.addBindValue(c.issuer);
        q.addBindValue(c.serial);  q.addBindValue(c.notBefore);q.addBindValue(c.notAfter);
        q.addBindValue(c.notExpired);q.addBindValue(c.hashAlg);q.addBindValue(c.thumbSha1);
        q.addBindValue(c.verifyResult); q.exec();
    }

    // ── 5. 文件关联检测测试数据 ──────────────────────────────────────────
    struct AssocData { QString ext, type, orig, curr, risk; };
    QList<AssocData> assocs = {
        {".exe","open","C:\\Windows\\System32\\shell32.dll,0",
         "C:\\Windows\\System32\\shell32.dll,0","low"},
        {".txt","open","C:\\Windows\\System32\\notepad.exe %1",
         "C:\\Windows\\System32\\notepad.exe %1","low"},
        {".pdf","open","C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe %1",
         "C:\\Users\\admin\\AppData\\Roaming\\update.exe %1","high"},
        {".doc","open","C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE /n %1",
         "C:\\Users\\admin\\AppData\\Roaming\\update.exe /n %1","high"},
        {".html","open","C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe %1",
         "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe %1","low"},
        {".zip","open","C:\\Program Files\\7-Zip\\7zFM.exe %1",
         "C:\\Program Files\\7-Zip\\7zFM.exe %1","low"},
    };

    q.prepare("INSERT INTO file_assoc_scan(ext,assoc_type,original_cmd,current_cmd,risk_level) VALUES(?,?,?,?,?)");
    for (auto &a : assocs) {
        q.addBindValue(a.ext); q.addBindValue(a.type);
        q.addBindValue(a.orig); q.addBindValue(a.curr); q.addBindValue(a.risk);
        q.exec();
    }

    // ── 6. 样本提取记录测试数据 ──────────────────────────────────────────
    struct SampleData { QString src, type, dest, md5, sha256, mtime, ctime, note; };
    QList<SampleData> samples = {
        {"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe","static",
         "C:\\Tools\\MalwareDetector\\samples\\suspicious_20251120_113000.exe",
         "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "2025-11-18 14:22:33","2025-11-18 14:22:33","静态检测样本提取"},
        {"C:\\Windows\\Temp\\svch0st.exe","static",
         "C:\\Tools\\MalwareDetector\\samples\\svch0st_20251120_113005.exe",
         "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
         "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
         "2025-11-19 08:15:00","2025-11-19 08:15:00","静态检测样本提取"},
        {"C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe","dynamic",
         "C:\\Tools\\MalwareDetector\\samples\\suspicious_dyn_20251120_113010.exe",
         "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "2025-11-18 14:22:33","2025-11-18 14:22:33","动态行为分析样本提取"},
        {"C:\\Users\\admin\\Desktop\\invoice_2025.pdf.exe","static",
         "C:\\Tools\\MalwareDetector\\samples\\invoice_20251120_113015.exe",
         "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
         "b3a8e0e1f9ab1827e1311d14c6baad0b3f7b2a9e5c6d7e8f9a0b1c2d3e4f5a6",
         "2025-11-20 09:30:00","2025-11-20 09:30:00","伪装PDF样本提取"},
    };

    q.prepare("INSERT INTO sample_extract(source_path,extract_type,sample_path,md5,sha256,original_mtime,original_ctime,note) VALUES(?,?,?,?,?,?,?,?)");
    for (auto &s : samples) {
        q.addBindValue(s.src);   q.addBindValue(s.type); q.addBindValue(s.dest);
        q.addBindValue(s.md5);   q.addBindValue(s.sha256);
        q.addBindValue(s.mtime); q.addBindValue(s.ctime); q.addBindValue(s.note);
        q.exec();
    }

    // ── 7. 操作日志审计测试数据 ──────────────────────────────────────────
    struct LogData { QString role, user, action, detail, result, ts; };
    QList<LogData> logs = {
        {"system_admin","admin","系统启动","恶意代码辅助检测系统启动成功","success","2025-11-20 08:30:00"},
        {"system_admin","admin","用户登录","系统管理员 admin 登录成功","success","2025-11-20 08:30:05"},
        {"system_admin","admin","系统信息采集","采集系统基本信息，共获取24项","success","2025-11-20 08:35:00"},
        {"system_admin","admin","系统信息采集","采集进程信息，共发现7个进程","success","2025-11-20 08:36:00"},
        {"system_admin","admin","系统信息采集","采集端口信息，共发现6个端口","success","2025-11-20 08:37:00"},
        {"sec_admin","secadmin","用户登录","安全管理员 secadmin 登录成功","success","2025-11-20 09:00:00"},
        {"sec_admin","secadmin","静态检测","对文件 suspicious.exe 执行静态检测","success","2025-11-20 09:05:00"},
        {"sec_admin","secadmin","静态检测","检测结果：高危，发现3条规则命中","success","2025-11-20 09:05:30"},
        {"sec_admin","secadmin","动态行为检测","启动动态行为分析 suspicious.exe","success","2025-11-20 09:10:00"},
        {"sec_admin","secadmin","动态行为检测","动态分析完成，发现8项可疑行为","success","2025-11-20 09:15:00"},
        {"sec_admin","secadmin","数字证书检测","对4个文件执行证书验证","success","2025-11-20 09:20:00"},
        {"sec_admin","secadmin","样本提取","提取样本 suspicious.exe 到样本库","success","2025-11-20 09:25:00"},
        {"sec_admin","secadmin","报告生成","生成检测报告 report_20251120.html","success","2025-11-20 09:30:00"},
        {"auditor","auditor","用户登录","安全审计员 auditor 登录成功","success","2025-11-20 10:00:00"},
        {"auditor","auditor","日志查询","查询2025-11-20操作日志，共14条","success","2025-11-20 10:05:00"},
        {"auditor","auditor","日志导出","导出操作日志到 audit_20251120.xlsx","success","2025-11-20 10:10:00"},
        {"system_admin","admin","病毒库更新","病毒库更新成功，版本：20251120","success","2025-11-20 11:00:00"},
        {"system_admin","admin","白名单管理","添加白名单条目：chrome.exe","success","2025-11-20 11:05:00"},
        {"sec_admin","secadmin","文件关联检测","检测文件关联，发现2项异常","success","2025-11-20 11:10:00"},
        {"system_admin","admin","系统设置","修改日志保留天数为90天","success","2025-11-20 11:15:00"},
        {"auditor","auditor","日志查询","查询安全管理员操作记录","success","2025-11-20 11:20:00"},
        {"sec_admin","secadmin","用户登录","安全管理员 secadmin 登录失败：密码错误","failed","2025-11-20 11:25:00"},
        {"sec_admin","secadmin","用户登录","安全管理员 secadmin 登录成功","success","2025-11-20 11:26:00"},
        {"system_admin","admin","用户退出","系统管理员 admin 正常退出","success","2025-11-20 11:30:00"},
    };

    q.prepare("INSERT INTO audit_log(role,username,action,detail,result,timestamp) VALUES(?,?,?,?,?,?)");
    for (auto &l : logs) {
        q.addBindValue(l.role);   q.addBindValue(l.user);
        q.addBindValue(l.action); q.addBindValue(l.detail);
        q.addBindValue(l.result); q.addBindValue(l.ts);
        q.exec();
    }

    // ── 8. 补充配置类设置数据 ──────────────────────────────────────────
    QList<QPair<QString,QString>> extraSettings = {
        {"dll_path",             "basic.dll"},
        {"virus_db_version",     "20251120"},
        {"virus_db_update_time", "2025-11-20 11:00:00"},
        {"auto_scan",            "false"},
        {"scan_on_startup",      "false"},
        {"realtime_protect",     "true"},
        {"log_retention_days",   "90"},
        {"report_output_dir",    "C:\\Tools\\MalwareDetector\\reports"},
        {"scan_depth",           "3"},
        {"max_file_size_mb",     "100"},
        {"enable_cloud_check",   "false"},
        {"whitelist",            R"(["chrome.exe","notepad.exe","explorer.exe","svchost.exe"])"},
        {"custom_rules",         R"([{"name":"自定义规则1","pattern":"CreateRemoteThread","type":"api","severity":"high"},{"name":"自定义规则2","pattern":"*.pdf.exe","type":"filename","severity":"high"}])"},
        {"users",                R"([{"username":"admin","role":"system_admin","password_hash":"Admin@123","enabled":true},{"username":"secadmin","role":"sec_admin","password_hash":"Sec@123","enabled":true},{"username":"auditor","role":"auditor","password_hash":"Audit@123","enabled":true}])"},
        {"system_name",          "恶意代码辅助检测系统"},
        {"system_version",       "V3.0.20251120"},
        {"cert_info",            "国家保密科技测评中心 认证产品"},
    };

    QSqlQuery sq(m_db);
    sq.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)");
    for (auto &kv : extraSettings) {
        sq.addBindValue(kv.first);
        sq.addBindValue(kv.second);
        sq.exec();
    }
}
