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
class SampleExtractPage;
class VulnDetectPage;
class ReportPage;
class GlobalSearchPage;
class UserManagePage;
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
    // 索引 0: 系统概览
    DashboardPage      *m_pgDashboard;   // 0
    // 基础信息 (1-11)
    SystemInfoPage     *m_pgSysInfo;     // 1
    NetworkInfoPage    *m_pgNetInfo;     // 2
    DiskInfoPage       *m_pgDiskInfo;    // 3
    ProcessInfoPage    *m_pgProcess;     // 4
    PortInfoPage       *m_pgPort;        // 5
    AutorunPage        *m_pgAutorun;     // 6
    ScheduledTaskPage  *m_pgScheduled;   // 7
    DriverInfoPage     *m_pgDriver;      // 8
    SharedResourcePage *m_pgShared;      // 9
    BrowserPluginPage  *m_pgBrowser;     // 10
    MemoryImagePage    *m_pgMemory;      // 11
    // 检测分析 (12-13)
    StaticScanPage     *m_pgStatic;      // 12
    DynamicScanPage    *m_pgDynamic;     // 13
    // 综合分析 (14-17)
    GlobalSearchPage   *m_pgGlobalSearch;// 14
    SampleExtractPage  *m_pgSample;      // 15
    VulnDetectPage     *m_pgVulnDetect;  // 16
    ReportPage         *m_pgReport;      // 17
    // 系统管理 (18-20)
    LogAuditPage       *m_pgLog;         // 18
    UserManagePage     *m_pgUserManage;  // 19
    SystemSettingsPage *m_pgSettings;    // 20

    BasicLibLoader *m_loader;
    QString         m_role;
    QString         m_username;
    int             m_currentPageIdx;
};

#endif // MAINWINDOW_H
