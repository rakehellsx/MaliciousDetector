#pragma once
#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QObject>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QString>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
#include <QList>
#include <QVariantMap>
#include <QVariantList>

// ── 日志记录结构体 ──────────────────────────────────────────────────────────
struct LogRecord {
    int      id;
    QString  role;        // system_admin / sec_admin / auditor
    QString  username;
    QString  action;
    QString  detail;
    QString  result;      // success / failed
    QString  ip_address;
    QDateTime timestamp;
};

class DatabaseManager : public QObject
{
    Q_OBJECT
public:
    static DatabaseManager* instance();
    bool init(const QString &dbPath = "");
    void close();

    // ── 系统设置 ────────────────────────────────────────────────────────────
    QString getSetting(const QString &key, const QString &defaultVal = "");
    bool    setSetting(const QString &key, const QString &value);

    // ── 日志审计 ────────────────────────────────────────────────────────────
    bool writeLog(const QString &role, const QString &username,
                  const QString &action, const QString &detail,
                  const QString &result = "success",
                  const QString &ip = "");
    QList<LogRecord> queryLogs(const QString &role = "",
                               const QString &type = "",
                               const QString &username = "",
                               const QDateTime &from = QDateTime(),
                               const QDateTime &to   = QDateTime(),
                               int limit = 500);

    // ── 系统基本信息 (sys_info) ─────────────────────────────────────────────
    // 返回 key-value 列表，每行 {key, value}
    QVariantList querySysInfo();

    // ── 网络信息 (net_info) ─────────────────────────────────────────────────
    // 返回行列表，每行 {name, ip, mask, gateway, mac, status}
    QVariantList queryNetInfo();

    // ── 硬盘信息 (disk_info) ────────────────────────────────────────────────
    // 返回行列表，每行 {drive, type, filesystem, total_gb, free_gb, used_pct, serial}
    QVariantList queryDiskInfo();

    // ── 进程信息 (process_info) ─────────────────────────────────────────────
    // 返回行列表，每行 {pid, name, path, user, cpu_pct, mem_mb, status, risk}
    QVariantList queryProcessInfo();

    // ── 端口信息 (port_info) ────────────────────────────────────────────────
    // 返回行列表，每行 {protocol, local_ip, local_port, remote_ip, remote_port, state, process_name, pid, risk}
    QVariantList queryPortInfo();

    // ── 自启动项 (autorun_info) ─────────────────────────────────────────────
    // type: reg / folder / rightclick / debugger
    QVariantList queryAutorunInfo(const QString &type = "");

    // ── 计划任务 (scheduled_task) ───────────────────────────────────────────
    QVariantList queryScheduledTasks();

    // ── 驱动信息 (driver_info) ──────────────────────────────────────────────
    QVariantList queryDriverInfo(const QString &typeFilter = "");

    // ── 共享资源 (shared_resource) ──────────────────────────────────────────
    QVariantList querySharedResources();

    // ── 浏览器插件 (browser_plugin) ─────────────────────────────────────────
    QVariantList queryBrowserPlugins(const QString &browser = "");

    // ── 内存映像 (memory_image) ─────────────────────────────────────────────
    QVariantMap  queryMemoryStatus();          // 内存运行状态 KV
    QVariantList queryKernelModules();         // 内核模块列表
    QVariantList queryProcessMemory();         // 进程内存映射列表

    // ── 静态检测 (static_scan) ──────────────────────────────────────────────
    QVariantList queryStaticScanFiles();       // 文件列表（id, file_name, file_size, file_type, risk_level）
    QVariantMap  queryStaticScanDetail(int id);// 单文件完整详情
    QVariantList queryStaticScanStrings(int id);
    QVariantList queryStaticScanRuleHits(int id);
    QVariantMap  queryStaticScanCert(int id);  // 证书信息（从 cert_scan 关联）

    // ── 动态行为检测 (dynamic_scan) ─────────────────────────────────────────
    // behavior_type: registry/file/process/network/ssdt/autorun/task/browser
    QVariantList queryDynamicScan(const QString &behaviorType = "");
    QVariantList queryProcessTree();           // 进程树（process 类型的层级数据）

    // ── 文件关联检测 (file_assoc_scan) ──────────────────────────────────────
    QVariantList queryFileAssoc();

    // ── 样本提取 (sample_extract) ───────────────────────────────────────────
    QVariantList querySampleExtract();

    // ── 检测报告汇总 ────────────────────────────────────────────────────────
    QVariantMap  queryReportSummary();         // 高危/中危/低危/已隔离 统计
    QVariantList queryReportThreats();         // 威胁列表（用于报告展示）

    // ── Dashboard ───────────────────────────────────────────────────────────
    QVariantMap  queryDashboardStats();        // 统计数字（高危/中危/低危/保护天数/病毒库版本）
    QVariantList queryRecentAlerts(int limit = 5); // 最近告警

    QString lastError() const { return m_lastError; }
    QString dbPath()    const { return m_dbPath; }

private:
    explicit DatabaseManager(QObject *parent = nullptr);
    static DatabaseManager *m_instance;
    QSqlDatabase m_db;
    QString      m_lastError;
    QString      m_dbPath;

    bool createTables();
    void insertTestData();

    // 工具函数：执行查询，返回 QVariantList（每行为 QVariantMap）
    QVariantList execSelect(const QString &sql, const QVariantList &binds = {});
    QVariantMap  execSelectOne(const QString &sql, const QVariantList &binds = {});
};

#endif // DATABASEMANAGER_H
