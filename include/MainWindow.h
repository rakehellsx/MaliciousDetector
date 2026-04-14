#pragma once
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTreeWidget>
#include <QIcon>
#include <QStackedWidget>
#include <QLabel>
#include <QPushButton>
#include <QStatusBar>
#include "BasicLibLoader.h"
#include "DatabaseManager.h"
#include "IconHelper.h"
#include "pages/BasePage.h"

// 前向声明所有页面
class DashboardPage;
class SystemInfoPage;
class NetworkInfoPage;
class DiskInfoPage;
class ProcessInfoPage;
class PortInfoPage;
class AutorunPage;
class ScheduledTaskPage;
class DriverInfoPage;
class SharedResourcePage;
class BrowserPluginPage;
class MemoryImagePage;
class StaticScanPage;
class DynamicScanPage;
// CertScanPage 已合并至 StaticScanPage 的数字证书 Tab，不再独立使用
class FileAssocPage;
class SampleExtractPage;
class ReportPage;
class LogAuditPage;
class SystemSettingsPage;

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(const QString &role, const QString &username,
                        QWidget *parent = nullptr);
    ~MainWindow();

    void setLibLoader(BasicLibLoader *loader);

private slots:
    void onNavItemClicked(QTreeWidgetItem *item, int col);
    void onLogout();
    void onRefreshCurrentPage();

private:
    void setupUi();
    void setupNav();
    void setupPages();
    void applyStyle();
    void switchPage(int index);
    QTreeWidgetItem* addNavItem(QTreeWidgetItem *parent,
                                const QIcon &icon,
                                const QString &text,
                                int pageIndex);

    // 布局控件
    QWidget        *m_centralWidget;
    QWidget        *m_sidebar;
    QTreeWidget    *m_navTree;
    QStackedWidget *m_stack;
    QLabel         *m_lblTitle;
    QLabel         *m_lblUser;
    QLabel         *m_lblVirusDb;
    QPushButton    *m_btnLogout;
    QPushButton    *m_btnRefresh;

    // 页面实例
    DashboardPage      *m_pgDashboard;
    SystemInfoPage     *m_pgSysInfo;
    NetworkInfoPage    *m_pgNetInfo;
    DiskInfoPage       *m_pgDiskInfo;
    ProcessInfoPage    *m_pgProcess;
    PortInfoPage       *m_pgPort;
    AutorunPage        *m_pgAutorun;
    ScheduledTaskPage  *m_pgScheduled;
    DriverInfoPage     *m_pgDriver;
    SharedResourcePage *m_pgShared;
    BrowserPluginPage  *m_pgBrowser;
    MemoryImagePage    *m_pgMemory;
    StaticScanPage     *m_pgStatic;
    DynamicScanPage    *m_pgDynamic;
    // m_pgCert 已删除：数字证书检测已合并至 StaticScanPage 的证书 Tab
    FileAssocPage      *m_pgFileAssoc;
    SampleExtractPage  *m_pgSample;
    ReportPage         *m_pgReport;
    LogAuditPage       *m_pgLog;
    SystemSettingsPage *m_pgSettings;

    BasicLibLoader *m_loader;
    QString         m_role;
    QString         m_username;
    int             m_currentPageIdx;
};

#endif // MAINWINDOW_H
