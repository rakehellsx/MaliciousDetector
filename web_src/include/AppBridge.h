#pragma once
#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>

/**
 * AppBridge — Qt/C++ 与 Web 前端的双向通信桥接
 *
 * 通过 QWebChannel 暴露给 JavaScript，JS 端通过
 *   new QWebChannel(qt.webChannelTransport, function(channel) {
 *       window.bridge = channel.objects.bridge;
 *   });
 * 访问本对象的所有 Q_INVOKABLE 方法和 Q_SIGNAL 信号。
 *
 * Win7 32位兼容：使用 Qt 5.6.x + MSVC2015 x86 编译
 */
class AppBridge : public QObject
{
    Q_OBJECT

public:
    explicit AppBridge(QObject *parent = nullptr);

    // ── 登录/登出 ──────────────────────────────────────────────
    Q_INVOKABLE void login(const QString &role, const QString &username, const QString &password);
    Q_INVOKABLE void logout();

    // ── 窗口控制 ────────────────────────────────────────────────
    Q_INVOKABLE void minimizeWindow();
    Q_INVOKABLE void maximizeWindow();
    Q_INVOKABLE void closeWindow();
    Q_INVOKABLE void toggleMaximize();

    // ── 数据查询接口（返回 JSON 字符串）────────────────────────
    Q_INVOKABLE QString getDashboardData();
    Q_INVOKABLE QString getSysInfoData();
    Q_INVOKABLE QString getNetInfoData();
    Q_INVOKABLE QString getDiskInfoData();
    Q_INVOKABLE QString getProcInfoData();
    Q_INVOKABLE QString getPortInfoData();
    Q_INVOKABLE QString getAutorunData();
    Q_INVOKABLE QString getScheduleData();
    Q_INVOKABLE QString getDriverData();
    Q_INVOKABLE QString getShareData();
    Q_INVOKABLE QString getBrowserPluginData();
    Q_INVOKABLE QString getMemoryData();
    Q_INVOKABLE QString getLogData();
    Q_INVOKABLE QString getUserData();
    Q_INVOKABLE QString getVulnData();

    // ── 进程详情（含模块/线程/句柄）────────────────────────────
    Q_INVOKABLE QString getProcDetail(const QString &procName);

    // ── 操作接口 ────────────────────────────────────────────────
    Q_INVOKABLE void exportData(const QString &pageId, const QString &format);
    Q_INVOKABLE void openFile(const QString &path);
    Q_INVOKABLE QString getAppVersion();
    Q_INVOKABLE QString getCurrentUser();
    Q_INVOKABLE QString getCurrentRole();

signals:
    // C++ → JS 推送事件
    void loginResult(bool success, const QString &message);
    void dataUpdated(const QString &pageId, const QString &jsonData);
    void notifyMessage(const QString &level, const QString &message);

private:
    QString m_currentUser;
    QString m_currentRole;
    bool    m_loggedIn;

    // 演示数据加载
    QString loadDemoJson(const QString &name) const;
};
