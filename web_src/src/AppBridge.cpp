/**
 * AppBridge.cpp
 * C++ <-> JavaScript 通信桥接实现
 * 所有数据均从 basic_test.db (SQLite) 读取真实数据
 */
#include "AppBridge.h"
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QSqlRecord>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDebug>
#include <QApplication>
#include <QWidget>

// ─────────────────────────────────────────────────────────────────────────────
// 辅助函数
// ─────────────────────────────────────────────────────────────────────────────

static QJsonValue toJsonVal(const QVariant &v)
{
    if (v.isNull() || !v.isValid()) return QJsonValue(QJsonValue::Null);
#if QT_VERSION >= QT_VERSION_CHECK(6,0,0)
    switch (v.typeId()) {
    case QMetaType::LongLong:
    case QMetaType::Int:
    case QMetaType::UInt:
    case QMetaType::ULongLong:
        return QJsonValue(v.toLongLong());
    case QMetaType::Double:
    case QMetaType::Float:
        return QJsonValue(v.toDouble());
    default:
        return QJsonValue(v.toString());
    }
#else
    switch (v.type()) {
    case QVariant::LongLong:
    case QVariant::Int:
    case QVariant::UInt:
    case QVariant::ULongLong:
        return QJsonValue(v.toLongLong());
    case QVariant::Double:
        return QJsonValue(v.toDouble());
    default:
        return QJsonValue(v.toString());
    }
#endif
}

// 将 QSqlQuery 当前行转为 QJsonObject（所有列）
static QJsonObject rowToJson(const QSqlQuery &q)
{
    QJsonObject o;
    QSqlRecord rec = q.record();
    for (int i = 0; i < rec.count(); ++i)
        o[rec.fieldName(i)] = toJsonVal(q.value(i));
    return o;
}

// 获取最新 snapshot_id
static int latestSnap(QSqlDatabase &d, const QString &table)
{
    QSqlQuery q(d);
    q.exec(QString("SELECT MAX(snapshot_id) FROM \"%1\"").arg(table));
    if (q.next() && !q.value(0).isNull())
        return q.value(0).toInt();
    return 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// 构造 / 析构
// ─────────────────────────────────────────────────────────────────────────────

AppBridge::AppBridge(QObject *parent)
    : QObject(parent)
    , m_dbReady(false)
    , m_loggedIn(false)
{
}

AppBridge::~AppBridge()
{
    closeDatabase();
}

// ─────────────────────────────────────────────────────────────────────────────
// 数据库管理
// ─────────────────────────────────────────────────────────────────────────────

bool AppBridge::initDatabase(const QString &dbPath)
{
    closeDatabase();

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "basic_conn");
    db.setDatabaseName(dbPath);
    if (!db.open()) {
        qWarning() << "[AppBridge] Cannot open DB:" << dbPath
                   << db.lastError().text();
        QSqlDatabase::removeDatabase("basic_conn");
        m_dbReady = false;
        return false;
    }
    m_dbPath  = dbPath;
    m_dbReady = true;
    qDebug() << "[AppBridge] DB opened:" << dbPath;
    return true;
}

void AppBridge::closeDatabase()
{
    if (QSqlDatabase::contains("basic_conn")) {
        QSqlDatabase::database("basic_conn").close();
        QSqlDatabase::removeDatabase("basic_conn");
    }
    m_dbReady = false;
}

QSqlDatabase AppBridge::db() const
{
    return QSqlDatabase::database("basic_conn");
}

// ─────────────────────────────────────────────────────────────────────────────
// 登录 / 登出
// ─────────────────────────────────────────────────────────────────────────────

void AppBridge::login(const QString &role, const QString &username, const QString &password)
{
    Q_UNUSED(password)
    bool ok = false;
    if (m_dbReady) {
        QSqlDatabase d = db();
        QSqlQuery q(d);
        q.prepare("SELECT id FROM sys_accounts WHERE username=? AND disabled=0 LIMIT 1");
        q.addBindValue(username);
        q.exec();
        ok = q.next();
    }
    // 演示兜底：admin 始终允许
    if (!ok && (username.toLower() == "admin" || username.isEmpty()))
        ok = true;

    if (ok) {
        m_loggedIn    = true;
        m_currentUser = username.isEmpty() ? "admin" : username;
        m_currentRole = role;
    }
    emit loginResult(ok, ok ? QString("") : QString("\xe7\x94\xa8\xe6\x88\xb7\xe5\x90\x8d\xe6\x88\x96\xe5\xaf\x86\xe7\xa0\x81\xe9\x94\x99\xe8\xaf\xaf"));
}

void AppBridge::logout()
{
    m_loggedIn = false;
    m_currentUser.clear();
    m_currentRole.clear();
}

// ─────────────────────────────────────────────────────────────────────────────
// 窗口控制
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// 工具函数
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getAppVersion()  { return QApplication::applicationVersion(); }
QString AppBridge::getCurrentUser() { return m_currentUser; }
QString AppBridge::getCurrentRole() { return m_currentRole; }

void AppBridge::exportData(const QString &pageId, const QString &format)
{
    Q_UNUSED(pageId) Q_UNUSED(format)
    emit notifyMessage("info", "\xe5\xaf\xbc\xe5\x87\xba\xe5\x8a\x9f\xe8\x83\xbd\xe5\xbc\x80\xe5\x8f\x91\xe4\xb8\xad...");
}

void AppBridge::openFile(const QString &path)
{
    Q_UNUSED(path)
    emit notifyMessage("info", "\xe6\x96\x87\xe4\xbb\xb6\xe6\x89\x93\xe5\xbc\x80\xe5\x8a\x9f\xe8\x83\xbd\xe5\xbc\x80\xe5\x8f\x91\xe4\xb8\xad...");
}

// ─────────────────────────────────────────────────────────────────────────────
// 仪表盘（汇总统计）
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getDashboardData()
{
    QJsonObject root;
    if (!m_dbReady) return QJsonDocument(root).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    QSqlQuery q(d);

    // 系统基本信息
    q.exec("SELECT product_name, display_version, computer_name, "
           "total_physical_mb, available_physical_mb, memory_load_percent "
           "FROM sys_info ORDER BY id DESC LIMIT 1");
    if (q.next()) {
        root["os_name"]      = toJsonVal(q.value("product_name"));
        root["os_version"]   = toJsonVal(q.value("display_version"));
        root["computer"]     = toJsonVal(q.value("computer_name"));
        root["total_mem_mb"] = toJsonVal(q.value("total_physical_mb"));
        root["avail_mem_mb"] = toJsonVal(q.value("available_physical_mb"));
        root["mem_usage"]    = toJsonVal(q.value("memory_load_percent"));
    }

    // 各模块计数
    struct { const char *key; const char *table; } counts[] = {
        {"proc_count",          "process_list"},
        {"port_count",          "port_connections"},
        {"driver_count",        "driver_list"},
        {"autorun_count",       "autorun_items"},
        {"kernel_module_count", "kernel_modules"},
        {"task_count",          "scheduled_tasks"},
        {"plugin_count",        "browser_plugins"},
        {"share_count",         "shared_resources"},
    };
    for (auto &c : counts) {
        int snap = latestSnap(d, c.table);
        q.prepare(QString("SELECT COUNT(*) FROM \"%1\" WHERE snapshot_id=?").arg(c.table));
        q.addBindValue(snap);
        q.exec();
        root[c.key] = q.next() ? q.value(0).toInt() : 0;
    }

    // 未签名驱动
    {
        int snap = latestSnap(d, "driver_list");
        q.prepare("SELECT COUNT(*) FROM driver_list WHERE snapshot_id=? AND is_signed=0");
        q.addBindValue(snap); q.exec();
        root["unsigned_driver_count"] = q.next() ? q.value(0).toInt() : 0;
    }
    // 未签名自启动
    {
        int snap = latestSnap(d, "autorun_items");
        q.prepare("SELECT COUNT(*) FROM autorun_items WHERE snapshot_id=? AND is_signed=0");
        q.addBindValue(snap); q.exec();
        root["unsigned_autorun_count"] = q.next() ? q.value(0).toInt() : 0;
    }

    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 模块01 系统信息
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getSysInfoData()
{
    QJsonObject root;
    if (!m_dbReady) return QJsonDocument(root).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    QSqlQuery q(d);

    q.exec("SELECT * FROM sys_info ORDER BY id DESC LIMIT 1");
    if (q.next()) root = rowToJson(q);

    // 账户子表
    int snap = latestSnap(d, "sys_accounts");
    QJsonArray accounts;
    q.prepare("SELECT * FROM sys_accounts WHERE snapshot_id=? ORDER BY id");
    q.addBindValue(snap); q.exec();
    while (q.next()) accounts.append(rowToJson(q));
    root["accounts"] = accounts;

    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 模块02 网络信息（网卡列表）
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getNetInfoData()
{
    QJsonArray arr;
    if (!m_dbReady) return QJsonDocument(arr).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    int snap = latestSnap(d, "network_adapters");
    QSqlQuery q(d);
    q.prepare("SELECT * FROM network_adapters WHERE snapshot_id=? ORDER BY id");
    q.addBindValue(snap); q.exec();
    while (q.next()) arr.append(rowToJson(q));
    return QJsonDocument(arr).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 模块03 硬盘信息
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getDiskInfoData()
{
    QJsonObject root;
    if (!m_dbReady) return QJsonDocument(root).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    QSqlQuery q(d);

    int snapP = latestSnap(d, "disk_physical");
    QJsonArray physical;
    q.prepare("SELECT * FROM disk_physical WHERE snapshot_id=? ORDER BY id");
    q.addBindValue(snapP); q.exec();
    while (q.next()) physical.append(rowToJson(q));
    root["physical"] = physical;

    int snapV = latestSnap(d, "disk_volumes");
    QJsonArray volumes;
    q.prepare("SELECT * FROM disk_volumes WHERE snapshot_id=? ORDER BY id");
    q.addBindValue(snapV); q.exec();
    while (q.next()) volumes.append(rowToJson(q));
    root["volumes"] = volumes;

    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 模块04 自启动项
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getAutorunData()
{
    QJsonArray arr;
    if (!m_dbReady) return QJsonDocument(arr).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    int snap = latestSnap(d, "autorun_items");
    QSqlQuery q(d);
    q.prepare("SELECT * FROM autorun_items WHERE snapshot_id=? ORDER BY id");
    q.addBindValue(snap); q.exec();
    while (q.next()) arr.append(rowToJson(q));
    return QJsonDocument(arr).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 模块05 进程信息
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getProcInfoData()
{
    QJsonArray arr;
    if (!m_dbReady) return QJsonDocument(arr).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    int snap = latestSnap(d, "process_list");
    QSqlQuery q(d);
    q.prepare("SELECT * FROM process_list WHERE snapshot_id=? ORDER BY pid");
    q.addBindValue(snap); q.exec();
    while (q.next()) arr.append(rowToJson(q));
    return QJsonDocument(arr).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 模块06 计划任务
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getScheduleData()
{
    QJsonArray arr;
    if (!m_dbReady) return QJsonDocument(arr).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    int snap = latestSnap(d, "scheduled_tasks");
    QSqlQuery q(d);
    q.prepare("SELECT * FROM scheduled_tasks WHERE snapshot_id=? ORDER BY id");
    q.addBindValue(snap); q.exec();
    while (q.next()) arr.append(rowToJson(q));
    return QJsonDocument(arr).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 模块07 端口信息
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getPortInfoData()
{
    QJsonArray arr;
    if (!m_dbReady) return QJsonDocument(arr).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    int snap = latestSnap(d, "port_connections");
    QSqlQuery q(d);
    q.prepare("SELECT * FROM port_connections WHERE snapshot_id=? ORDER BY local_port");
    q.addBindValue(snap); q.exec();
    while (q.next()) arr.append(rowToJson(q));
    return QJsonDocument(arr).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 模块08 共享资源
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getShareData()
{
    QJsonArray arr;
    if (!m_dbReady) return QJsonDocument(arr).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    int snap = latestSnap(d, "shared_resources");
    QSqlQuery q(d);
    q.prepare("SELECT * FROM shared_resources WHERE snapshot_id=? ORDER BY id");
    q.addBindValue(snap); q.exec();
    while (q.next()) arr.append(rowToJson(q));
    return QJsonDocument(arr).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 模块09 驱动信息
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getDriverData()
{
    QJsonArray arr;
    if (!m_dbReady) return QJsonDocument(arr).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    int snap = latestSnap(d, "driver_list");
    QSqlQuery q(d);
    q.prepare("SELECT * FROM driver_list WHERE snapshot_id=? ORDER BY driver_name");
    q.addBindValue(snap); q.exec();
    while (q.next()) arr.append(rowToJson(q));
    return QJsonDocument(arr).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 模块10 浏览器插件
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getBrowserPluginData()
{
    QJsonArray arr;
    if (!m_dbReady) return QJsonDocument(arr).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    int snap = latestSnap(d, "browser_plugins");
    QSqlQuery q(d);
    q.prepare("SELECT * FROM browser_plugins WHERE snapshot_id=? ORDER BY browser, id");
    q.addBindValue(snap); q.exec();
    while (q.next()) arr.append(rowToJson(q));
    return QJsonDocument(arr).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 模块11 内存映像（内核模块）
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getMemoryData()
{
    QJsonObject root;
    if (!m_dbReady) return QJsonDocument(root).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    int snap = latestSnap(d, "kernel_modules");
    QSqlQuery q(d);

    QJsonArray modules;
    q.prepare("SELECT * FROM kernel_modules WHERE snapshot_id=? ORDER BY load_order");
    q.addBindValue(snap); q.exec();
    while (q.next()) modules.append(rowToJson(q));
    root["kernel_modules"] = modules;

    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 用户管理（sys_accounts）
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getUserData()
{
    QJsonArray arr;
    if (!m_dbReady) return QJsonDocument(arr).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    int snap = latestSnap(d, "sys_accounts");
    QSqlQuery q(d);
    q.prepare("SELECT * FROM sys_accounts WHERE snapshot_id=? ORDER BY id");
    q.addBindValue(snap); q.exec();
    while (q.next()) arr.append(rowToJson(q));
    return QJsonDocument(arr).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 漏洞监测（暂无专属表）
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getVulnData()
{
    QJsonArray arr;
    return QJsonDocument(arr).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 日志审计（暂无专属表）
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getLogData()
{
    QJsonArray arr;
    return QJsonDocument(arr).toJson(QJsonDocument::Compact);
}

// ─────────────────────────────────────────────────────────────────────────────
// 进程详情
// ─────────────────────────────────────────────────────────────────────────────

QString AppBridge::getProcDetail(const QString &procName)
{
    QJsonObject root;
    if (!m_dbReady) return QJsonDocument(root).toJson(QJsonDocument::Compact);

    QSqlDatabase d = db();
    int snap = latestSnap(d, "process_list");
    QSqlQuery q(d);
    q.prepare("SELECT * FROM process_list WHERE snapshot_id=? AND process_name=? LIMIT 1");
    q.addBindValue(snap);
    q.addBindValue(procName);
    q.exec();
    if (q.next()) root = rowToJson(q);
    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}
