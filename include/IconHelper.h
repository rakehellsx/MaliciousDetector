#pragma once
#include <QIcon>
#include <QPixmap>
#include <QString>
#include <QSize>
#include <QCoreApplication>
#include <QDir>

/**
 * IconHelper - 统一图标加载工具类
 * 所有图标从 resources/icons/ 目录加载 PNG 文件
 * 若文件不存在则返回空图标（不崩溃）
 */
class IconHelper
{
public:
    // 获取图标根目录（相对于可执行文件）
    static QString iconDir() {
        // 优先从可执行文件同级目录查找
        QString base = QCoreApplication::applicationDirPath();
        QString path = base + "/resources/icons/";
        if (QDir(path).exists()) return path;
        // 开发模式：从项目根目录查找
        path = base + "/../resources/icons/";
        if (QDir(path).exists()) return QDir::cleanPath(path) + "/";
        // 再往上一级
        path = base + "/../../resources/icons/";
        if (QDir(path).exists()) return QDir::cleanPath(path) + "/";
        return base + "/resources/icons/";
    }

    static QIcon icon(const QString &name, const QSize &size = QSize(20,20)) {
        QString path = iconDir() + name + ".png";
        QPixmap pm(path);
        if (pm.isNull()) return QIcon();
        return QIcon(pm.scaled(size, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    }

    static QPixmap pixmap(const QString &name, int size = 20) {
        QString path = iconDir() + name + ".png";
        QPixmap pm(path);
        if (pm.isNull()) return QPixmap();
        return pm.scaled(size, size, Qt::KeepAspectRatio, Qt::SmoothTransformation);
    }

    static QLabel* iconLabel(const QString &name, int size = 20, QWidget *parent = nullptr) {
        QLabel *lbl = new QLabel(parent);
        lbl->setPixmap(pixmap(name, size));
        lbl->setFixedSize(size, size);
        lbl->setScaledContents(true);
        return lbl;
    }

    // ── 常用图标快捷方法 ─────────────────────────────────────
    static QIcon appIcon()        { return icon("app", {32,32}); }
    static QIcon navDashboard()   { return icon("nav_dashboard"); }
    static QIcon navSysInfo()     { return icon("nav_sysinfo"); }
    static QIcon navNetwork()     { return icon("nav_network"); }
    static QIcon navDisk()        { return icon("nav_disk"); }
    static QIcon navProcess()     { return icon("nav_process"); }
    static QIcon navPort()        { return icon("nav_port"); }
    static QIcon navAutorun()     { return icon("nav_autorun"); }
    static QIcon navScheduled()   { return icon("nav_scheduled"); }
    static QIcon navDriver()      { return icon("nav_driver"); }
    static QIcon navShared()      { return icon("nav_shared"); }
    static QIcon navPlugin()      { return icon("nav_plugin"); }
    static QIcon navMemory()      { return icon("nav_memory"); }
    static QIcon navStatic()      { return icon("nav_static"); }
    static QIcon navDynamic()     { return icon("nav_dynamic"); }
    static QIcon navCert()        { return icon("nav_cert"); }
    static QIcon navFileAssoc()   { return icon("nav_fileassoc"); }
    static QIcon navSample()      { return icon("nav_sample"); }
    static QIcon navReport()      { return icon("nav_report"); }
    static QIcon navLog()         { return icon("nav_log"); }
    static QIcon navSettings()    { return icon("nav_settings"); }

    static QIcon groupCollect()   { return icon("group_collect"); }
    static QIcon groupScan()      { return icon("group_scan"); }
    static QIcon groupResult()    { return icon("group_result"); }

    static QIcon statusSafe()     { return icon("status_safe",    {16,16}); }
    static QIcon statusWarning()  { return icon("status_warning", {16,16}); }
    static QIcon statusDanger()   { return icon("status_danger",  {16,16}); }
    static QIcon statusInfo()     { return icon("status_info",    {16,16}); }

    static QIcon riskHigh()       { return icon("risk_high",   {14,14}); }
    static QIcon riskMedium()     { return icon("risk_medium", {14,14}); }
    static QIcon riskLow()        { return icon("risk_low",    {14,14}); }
    static QIcon riskSafe()       { return icon("risk_safe",   {14,14}); }

    static QIcon btnRefresh()     { return icon("btn_refresh",  {16,16}); }
    static QIcon btnExport()      { return icon("btn_export",   {16,16}); }
    static QIcon btnScan()        { return icon("btn_scan",     {16,16}); }
    static QIcon btnAdd()         { return icon("btn_add",      {16,16}); }
    static QIcon btnDelete()      { return icon("btn_delete",   {16,16}); }
    static QIcon btnDetail()      { return icon("btn_detail",   {16,16}); }
    static QIcon btnUpdate()      { return icon("btn_update",   {16,16}); }
    static QIcon btnBrowse()      { return icon("btn_browse",   {16,16}); }
    static QIcon btnLogout()      { return icon("btn_logout",   {16,16}); }

    static QIcon userAdmin()      { return icon("user_admin",    {20,20}); }
    static QIcon userSecAdmin()   { return icon("user_secadmin", {20,20}); }
    static QIcon userAuditor()    { return icon("user_auditor",  {20,20}); }

    static QIcon usbKey()         { return icon("usbkey",               {20,20}); }
    static QIcon usbKeyConn()     { return icon("usbkey_connected",     {20,20}); }
    static QIcon usbKeyDisconn()  { return icon("usbkey_disconnected",  {20,20}); }
};
