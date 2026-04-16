#pragma once
#include <QObject>
#include <QString>
#include <QSqlDatabase>

/**
 * AppBridge — Qt/C++ 与 Web 前端的双向通信桥接
 *
 * 通过 QWebChannel 暴露给 JavaScript，JS 端通过
 *   new QWebChannel(qt.webChannelTransport, function(channel) {
 *       window.bridge = channel.objects.bridge;
 *   });
 * 访问本对象的所有 Q_INVOKABLE 方法和 Q_SIGNAL 信号。
 *
 * 数据来源：basic_test.db（SQLite），通过 initDatabase() 初始化。
 * Win7 32位兼容：使用 Qt 5.6.x + MSVC2015 x86 编译。
 */
class AppBridge : public QObject
{
    Q_OBJECT

public:
    explicit AppBridge(QObject *parent = nullptr);
    ~AppBridge();

    // ── 数据库初始化（由 MainWindow 在启动时调用）──────────────
    bool initDatabase(const QString &dbPath);
    void closeDatabase();

    // ── 登录/登出 ──────────────────────────────────────────────
    Q_INVOKABLE void login(const QString &role, const QString &username, const QString &password);
    Q_INVOKABLE void logout();

    // ── 窗口控制 ────────────────────────────────────────────────
    Q_INVOKABLE void minimizeWindow();
    Q_INVOKABLE void maximizeWindow();
    Q_INVOKABLE void closeWindow();
    Q_INVOKABLE void toggleMaximize();

    // ── 数据查询接口（返回 JSON 字符串）────────────────────────
    Q_INVOKABLE QString getDashboardData();      // 仪表盘汇总
    Q_INVOKABLE QString getSysInfoData();        // 模块01 系统信息 + 账户
    Q_INVOKABLE QString getNetInfoData();        // 模块02 网络适配器
    Q_INVOKABLE QString getDiskInfoData();       // 模块03 磁盘（物理+卷）
    Q_INVOKABLE QString getAutorunData();        // 模块04 自启动项
    Q_INVOKABLE QString getProcInfoData();       // 模块05 进程列表
    Q_INVOKABLE QString getScheduleData();       // 模块06 计划任务
    Q_INVOKABLE QString getPortInfoData();       // 模块07 端口连接
    Q_INVOKABLE QString getShareData();          // 模块08 共享资源
    Q_INVOKABLE QString getDriverData();         // 模块09 驱动列表
    Q_INVOKABLE QString getBrowserPluginData();  // 模块10 浏览器插件
    Q_INVOKABLE QString getMemoryData();         // 模块11 内核模块
    Q_INVOKABLE QString getLogData();            // 日志审计（暂无专属表）
    Q_INVOKABLE QString getUserData();           // 用户管理（sys_accounts）
    Q_INVOKABLE QString getVulnData();           // 漏洞监测（暂无专属表）

    // ── 进程详情 ────────────────────────────────────────────────
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
    void windowMinimize();
    void windowMaximize();
    void windowToggleMax();
    void windowClose();

private:
    QSqlDatabase db() const;

    QString m_dbPath;
    bool    m_dbReady;
    bool    m_loggedIn;
    QString m_currentUser;
    QString m_currentRole;
};
