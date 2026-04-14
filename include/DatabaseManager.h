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
#include <QList>

struct LogRecord {
    int      id;
    QString  role;        // 操作角色：system_admin / sec_admin / auditor
    QString  username;
    QString  action;      // 操作类型
    QString  detail;      // 操作详情
    QString  result;      // success / failed
    QDateTime timestamp;
};

struct ScanRecord {
    int      id;
    QString  moduleName;
    QString  paramsJson;
    QString  resultJson;
    QDateTime createdAt;
};

class DatabaseManager : public QObject
{
    Q_OBJECT
public:
    static DatabaseManager* instance();
    bool init(const QString &dbPath = "");
    void close();

    // 日志操作
    bool writeLog(const QString &role, const QString &username,
                  const QString &action, const QString &detail,
                  const QString &result = "success");
    QList<LogRecord> queryLogs(const QString &role = "",
                               const QDateTime &from = QDateTime(),
                               const QDateTime &to   = QDateTime(),
                               int limit = 500);

    // 扫描结果操作
    bool saveScanResult(const QString &moduleName,
                        const QString &paramsJson,
                        const QString &resultJson);
    QList<ScanRecord> queryScanHistory(const QString &moduleName = "",
                                       int limit = 100);

    // 系统设置
    QString getSetting(const QString &key, const QString &defaultVal = "");
    bool    setSetting(const QString &key, const QString &value);

    QString lastError() const { return m_lastError; }
    QString dbPath()    const { return m_dbPath; }

private:
    explicit DatabaseManager(QObject *parent = nullptr);
    static DatabaseManager *m_instance;
    QSqlDatabase m_db;
    QString      m_lastError;
    QString      m_dbPath;

    bool createTables();
    void insertTestData();  // 插入演示测试数据
};

#endif // DATABASEMANAGER_H
