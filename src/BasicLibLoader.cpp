#include "BasicLibLoader.h"
#include <QDebug>

BasicLibLoader::BasicLibLoader(QObject *parent)
    : QObject(parent)
{
}

BasicLibLoader::~BasicLibLoader()
{
    unload();
}

bool BasicLibLoader::load(const QString &dllPath)
{
    if (m_loaded) unload();

    m_lib.setFileName(dllPath);
    if (!m_lib.load()) {
        m_lastError = m_lib.errorString();
        emit loadError(m_lastError);
        return false;
    }

    // 解析所有函数指针
    m_fnInit      = (FnInitDetectSystem)   m_lib.resolve("InitDetectSystem");
    m_fnCleanup   = (FnCleanupDetectSystem)m_lib.resolve("CleanupDetectSystem");
    m_fnFree      = (FnFreeJsonString)     m_lib.resolve("FreeJsonString");
    m_fnSysInfo   = (FnGetSystemInfo)      m_lib.resolve("GetSystemInfo");
    m_fnNetInfo   = (FnGetNetworkInfo)     m_lib.resolve("GetNetworkInfo");
    m_fnDiskInfo  = (FnGetDiskInfo)        m_lib.resolve("GetDiskInfo");
    m_fnAutorun   = (FnGetAutorunInfo)     m_lib.resolve("GetAutorunInfo");
    m_fnProcess   = (FnGetProcessInfo)     m_lib.resolve("GetProcessInfo");
    m_fnScheduled = (FnGetScheduledTasks)  m_lib.resolve("GetScheduledTasks");
    m_fnPort      = (FnGetPortInfo)        m_lib.resolve("GetPortInfo");
    m_fnShared    = (FnGetSharedResources) m_lib.resolve("GetSharedResources");
    m_fnDriver    = (FnGetDriverInfo)      m_lib.resolve("GetDriverInfo");
    m_fnBrowser   = (FnGetBrowserPlugins)  m_lib.resolve("GetBrowserPlugins");
    m_fnMemory    = (FnGetMemoryImageInfo) m_lib.resolve("GetMemoryImageInfo");
    m_fnCert      = (FnGetCertInfo)        m_lib.resolve("GetCertInfo");
    m_fnBatchCert = (FnBatchGetCertInfo)   m_lib.resolve("BatchGetCertInfo");
    m_fnQuerySave = (FnQueryModuleAndSave) m_lib.resolve("QueryModuleAndSave");
    m_fnHistory   = (FnQueryHistory)       m_lib.resolve("QueryHistory");

    if (!m_fnFree || !m_fnSysInfo) {
        m_lastError = "关键函数符号解析失败，请确认 basic.dll 版本正确";
        m_lib.unload();
        emit loadError(m_lastError);
        return false;
    }

    m_loaded = true;
    return true;
}

void BasicLibLoader::unload()
{
    if (m_loaded && m_fnCleanup) {
        m_fnCleanup();
    }
    if (m_lib.isLoaded()) {
        m_lib.unload();
    }
    m_loaded = false;
    // 清空所有函数指针
    m_fnInit = nullptr; m_fnCleanup = nullptr; m_fnFree = nullptr;
    m_fnSysInfo = nullptr; m_fnNetInfo = nullptr; m_fnDiskInfo = nullptr;
    m_fnAutorun = nullptr; m_fnProcess = nullptr; m_fnScheduled = nullptr;
    m_fnPort = nullptr; m_fnShared = nullptr; m_fnDriver = nullptr;
    m_fnBrowser = nullptr; m_fnMemory = nullptr; m_fnCert = nullptr;
    m_fnBatchCert = nullptr; m_fnQuerySave = nullptr; m_fnHistory = nullptr;
}

bool BasicLibLoader::isLoaded() const { return m_loaded; }
QString BasicLibLoader::lastError() const { return m_lastError; }

bool BasicLibLoader::initSystem()
{
    if (!m_loaded || !m_fnInit) return false;
    return m_fnInit() == 0;
}

void BasicLibLoader::cleanupSystem()
{
    if (m_loaded && m_fnCleanup) m_fnCleanup();
}

// ── 工具函数 ──────────────────────────────────────────────────────────────

QJsonObject BasicLibLoader::parseResult(char *rawJson)
{
    if (!rawJson) {
        return QJsonObject{{"error", "DLL 返回空指针"}};
    }
    QString jsonStr = QString::fromUtf8(rawJson);
    // 必须用 DLL 提供的 FreeJsonString 释放内存
    if (m_fnFree) m_fnFree(rawJson);

    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(jsonStr.toUtf8(), &err);
    if (err.error != QJsonParseError::NoError) {
        return QJsonObject{{"error", "JSON 解析失败: " + err.errorString()},
                           {"raw", jsonStr}};
    }
    return doc.object();
}

QJsonObject BasicLibLoader::callFunc(std::function<char*(const char*)> fn,
                                     const QJsonObject &params)
{
    if (!m_loaded) return QJsonObject{{"error", "动态库未加载"}};
    QJsonDocument doc(params);
    QByteArray paramsBytes = doc.toJson(QJsonDocument::Compact);
    char *raw = fn(paramsBytes.constData());
    return parseResult(raw);
}

// ── 各模块实现 ────────────────────────────────────────────────────────────

QJsonObject BasicLibLoader::getSystemInfo()
{
    if (!m_fnSysInfo) return {{"error","符号未找到"}};
    return callFunc([this](const char* p){ return m_fnSysInfo(p); }, QJsonObject{});
}

QJsonObject BasicLibLoader::getNetworkInfo()
{
    if (!m_fnNetInfo) return {{"error","符号未找到"}};
    return callFunc([this](const char* p){ return m_fnNetInfo(p); }, QJsonObject{});
}

QJsonObject BasicLibLoader::getDiskInfo()
{
    if (!m_fnDiskInfo) return {{"error","符号未找到"}};
    return callFunc([this](const char* p){ return m_fnDiskInfo(p); }, QJsonObject{});
}

QJsonObject BasicLibLoader::getAutorunInfo()
{
    if (!m_fnAutorun) return {{"error","符号未找到"}};
    return callFunc([this](const char* p){ return m_fnAutorun(p); }, QJsonObject{});
}

QJsonObject BasicLibLoader::getProcessInfo()
{
    if (!m_fnProcess) return {{"error","符号未找到"}};
    return callFunc([this](const char* p){ return m_fnProcess(p); }, QJsonObject{});
}

QJsonObject BasicLibLoader::getScheduledTasks()
{
    if (!m_fnScheduled) return {{"error","符号未找到"}};
    return callFunc([this](const char* p){ return m_fnScheduled(p); }, QJsonObject{});
}

QJsonObject BasicLibLoader::getPortInfo()
{
    if (!m_fnPort) return {{"error","符号未找到"}};
    return callFunc([this](const char* p){ return m_fnPort(p); }, QJsonObject{});
}

QJsonObject BasicLibLoader::getSharedResources()
{
    if (!m_fnShared) return {{"error","符号未找到"}};
    return callFunc([this](const char* p){ return m_fnShared(p); }, QJsonObject{});
}

QJsonObject BasicLibLoader::getDriverInfo()
{
    if (!m_fnDriver) return {{"error","符号未找到"}};
    return callFunc([this](const char* p){ return m_fnDriver(p); }, QJsonObject{});
}

QJsonObject BasicLibLoader::getBrowserPlugins()
{
    if (!m_fnBrowser) return {{"error","符号未找到"}};
    return callFunc([this](const char* p){ return m_fnBrowser(p); }, QJsonObject{});
}

QJsonObject BasicLibLoader::getMemoryImageInfo(bool saveDump, int dumpPid,
                                                const QString &dumpPath)
{
    if (!m_fnMemory) return {{"error","符号未找到"}};
    QJsonObject params;
    params["save_dump"] = saveDump;
    if (saveDump) {
        params["dump_pid"]  = dumpPid;
        params["dump_path"] = dumpPath.isEmpty() ? "C:\\memdump.dmp" : dumpPath;
    }
    return callFunc([this](const char* p){ return m_fnMemory(p); }, params);
}

QJsonObject BasicLibLoader::getCertInfo(const QString &filePath,
                                         bool checkRevocation, bool includeChain)
{
    if (!m_fnCert) return {{"error","符号未找到"}};
    QJsonObject params;
    params["file_path"]        = filePath;
    params["check_revocation"] = checkRevocation;
    params["include_chain"]    = includeChain;
    return callFunc([this](const char* p){ return m_fnCert(p); }, params);
}

QJsonObject BasicLibLoader::batchGetCertInfo(const QStringList &files,
                                              bool checkRevocation, bool includeChain)
{
    if (!m_fnBatchCert) return {{"error","符号未找到"}};
    QJsonObject params;
    QJsonArray arr;
    for (const QString &f : files) arr.append(f);
    params["files"]            = arr;
    params["check_revocation"] = checkRevocation;
    params["include_chain"]    = includeChain;
    return callFunc([this](const char* p){ return m_fnBatchCert(p); }, params);
}

QJsonObject BasicLibLoader::queryModuleAndSave(const QString &moduleName,
                                                const QJsonObject &moduleParams,
                                                const QString &dbPath, bool saveToDb)
{
    if (!m_fnQuerySave) return {{"error","符号未找到"}};
    QJsonObject params;
    params["module_name"]   = moduleName;
    params["module_params"] = moduleParams;
    params["save_to_db"]    = saveToDb;
    if (!dbPath.isEmpty()) params["db_path"] = dbPath;
    return callFunc([this](const char* p){ return m_fnQuerySave(p); }, params);
}

QJsonObject BasicLibLoader::queryHistory(const QString &moduleName,
                                          const QString &dbPath, int limit)
{
    if (!m_fnHistory) return {{"error","符号未找到"}};
    QJsonObject params;
    if (!moduleName.isEmpty()) params["module_name"] = moduleName;
    if (!dbPath.isEmpty())     params["db_path"]     = dbPath;
    params["limit"] = limit;
    return callFunc([this](const char* p){ return m_fnHistory(p); }, params);
}
