#pragma once
#ifndef BASICLIBLOADER_H
#define BASICLIBLOADER_H

#include <QObject>
#include <QLibrary>
#include <QString>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <functional>

/**
 * @brief BasicLibLoader - basic.dll 动态库加载与调用封装
 *
 * 使用 QLibrary 在运行时动态加载 basic.dll，
 * 通过函数指针调用各检测模块，返回 QJsonObject 结果。
 * 所有接口均为线程安全的同步调用。
 */
class BasicLibLoader : public QObject
{
    Q_OBJECT

public:
    explicit BasicLibLoader(QObject *parent = nullptr);
    ~BasicLibLoader();

    // 加载/卸载动态库
    bool    load(const QString &dllPath);
    void    unload();
    bool    isLoaded() const;
    QString lastError() const;

    // ── 生命周期 ──────────────────────────────────────────
    bool initSystem();
    void cleanupSystem();

    // ── 各模块调用（返回 QJsonObject，失败时含 "error" 字段）──
    QJsonObject getSystemInfo();
    QJsonObject getNetworkInfo();
    QJsonObject getDiskInfo();
    QJsonObject getAutorunInfo();
    QJsonObject getProcessInfo();
    QJsonObject getScheduledTasks();
    QJsonObject getPortInfo();
    QJsonObject getSharedResources();
    QJsonObject getDriverInfo();
    QJsonObject getBrowserPlugins();
    QJsonObject getMemoryImageInfo(bool saveDump = false,
                                   int  dumpPid  = 0,
                                   const QString &dumpPath = "");
    QJsonObject getCertInfo(const QString &filePath,
                            bool checkRevocation = false,
                            bool includeChain    = true);
    QJsonObject batchGetCertInfo(const QStringList &files,
                                 bool checkRevocation = false,
                                 bool includeChain    = false);

    // ── 统一查询与持久化 ──────────────────────────────────
    QJsonObject queryModuleAndSave(const QString &moduleName,
                                   const QJsonObject &moduleParams = QJsonObject(),
                                   const QString &dbPath = "",
                                   bool saveToDb = true);
    QJsonObject queryHistory(const QString &moduleName = "",
                             const QString &dbPath = "",
                             int limit = 100);

signals:
    void loadError(const QString &msg);

private:
    // 函数指针类型定义
    typedef int   (*FnInitDetectSystem)();
    typedef void  (*FnCleanupDetectSystem)();
    typedef void  (*FnFreeJsonString)(char*);
    typedef char* (*FnGetSystemInfo)(const char*);
    typedef char* (*FnGetNetworkInfo)(const char*);
    typedef char* (*FnGetDiskInfo)(const char*);
    typedef char* (*FnGetAutorunInfo)(const char*);
    typedef char* (*FnGetProcessInfo)(const char*);
    typedef char* (*FnGetScheduledTasks)(const char*);
    typedef char* (*FnGetPortInfo)(const char*);
    typedef char* (*FnGetSharedResources)(const char*);
    typedef char* (*FnGetDriverInfo)(const char*);
    typedef char* (*FnGetBrowserPlugins)(const char*);
    typedef char* (*FnGetMemoryImageInfo)(const char*);
    typedef char* (*FnGetCertInfo)(const char*);
    typedef char* (*FnBatchGetCertInfo)(const char*);
    typedef char* (*FnQueryModuleAndSave)(const char*);
    typedef char* (*FnQueryHistory)(const char*);

    // 函数指针成员
    FnInitDetectSystem    m_fnInit       = nullptr;
    FnCleanupDetectSystem m_fnCleanup    = nullptr;
    FnFreeJsonString      m_fnFree       = nullptr;
    FnGetSystemInfo       m_fnSysInfo    = nullptr;
    FnGetNetworkInfo      m_fnNetInfo    = nullptr;
    FnGetDiskInfo         m_fnDiskInfo   = nullptr;
    FnGetAutorunInfo      m_fnAutorun    = nullptr;
    FnGetProcessInfo      m_fnProcess    = nullptr;
    FnGetScheduledTasks   m_fnScheduled  = nullptr;
    FnGetPortInfo         m_fnPort       = nullptr;
    FnGetSharedResources  m_fnShared     = nullptr;
    FnGetDriverInfo       m_fnDriver     = nullptr;
    FnGetBrowserPlugins   m_fnBrowser    = nullptr;
    FnGetMemoryImageInfo  m_fnMemory     = nullptr;
    FnGetCertInfo         m_fnCert       = nullptr;
    FnBatchGetCertInfo    m_fnBatchCert  = nullptr;
    FnQueryModuleAndSave  m_fnQuerySave  = nullptr;
    FnQueryHistory        m_fnHistory    = nullptr;

    QLibrary  m_lib;
    QString   m_lastError;
    bool      m_loaded = false;

    // 工具函数：调用函数指针并解析JSON
    QJsonObject callFunc(std::function<char*(const char*)> fn,
                         const QJsonObject &params);
    QJsonObject parseResult(char *rawJson);
};

#endif // BASICLIBLOADER_H
