#include "MainWindow.h"
#include "IconHelper.h"
#include "pages/DashboardPage.h"
#include "pages/SystemInfoPage.h"
#include "pages/NetworkInfoPage.h"
#include "pages/DiskInfoPage.h"
#include "pages/ProcessInfoPage.h"
#include "pages/PortInfoPage.h"
#include "pages/AutorunPage.h"
#include "pages/ScheduledTaskPage.h"
#include "pages/DriverInfoPage.h"
#include "pages/SharedResourcePage.h"
#include "pages/BrowserPluginPage.h"
#include "pages/MemoryImagePage.h"
#include "pages/StaticScanPage.h"
#include "pages/DynamicScanPage.h"
#include "pages/SampleExtractPage.h"
#include "pages/VulnDetectPage.h"
#include "pages/ReportPage.h"
#include "pages/GlobalSearchPage.h"
#include "pages/UserManagePage.h"
#include "pages/LogAuditPage.h"
#include "pages/SystemSettingsPage.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QFrame>
#include <QDateTime>
#include <QApplication>
#include <QMessageBox>

MainWindow::MainWindow(const QString &role, const QString &username, QWidget *parent)
    : QMainWindow(parent), m_role(role), m_username(username),
      m_loader(nullptr), m_currentPageIdx(0)
{
    setWindowTitle("恶意代码辅助检测系统 V3.0");
    setWindowIcon(IconHelper::appIcon());
    setMinimumSize(1280, 800);
    resize(1440, 900);
    setupUi();
    setupNav();
    setupPages();
    applyStyle();
    switchPage(0);
}

MainWindow::~MainWindow() {}

void MainWindow::setLibLoader(BasicLibLoader *loader)
{
    m_loader = loader;
    auto setLoader = [&](BasePage *p) {
        if (p) { p->setLoader(loader); p->setRole(m_role); p->setUsername(m_username); }
    };
    setLoader(m_pgDashboard);    setLoader(m_pgSysInfo);      setLoader(m_pgNetInfo);
    setLoader(m_pgDiskInfo);     setLoader(m_pgProcess);      setLoader(m_pgPort);
    setLoader(m_pgAutorun);      setLoader(m_pgScheduled);    setLoader(m_pgDriver);
    setLoader(m_pgShared);       setLoader(m_pgBrowser);      setLoader(m_pgMemory);
    setLoader(m_pgStatic);       setLoader(m_pgDynamic);
    setLoader(m_pgGlobalSearch); setLoader(m_pgSample);       setLoader(m_pgVulnDetect);
    setLoader(m_pgReport);
    setLoader(m_pgLog);          setLoader(m_pgUserManage);   setLoader(m_pgSettings);
}

void MainWindow::setupUi()
{
    m_centralWidget = new QWidget;
    setCentralWidget(m_centralWidget);
    QHBoxLayout *mainLay = new QHBoxLayout(m_centralWidget);
    mainLay->setContentsMargins(0, 0, 0, 0);
    mainLay->setSpacing(0);

    // ── 侧边栏 ──────────────────────────────────────────────
    m_sidebar = new QWidget;
    m_sidebar->setObjectName("sidebar");
    m_sidebar->setFixedWidth(220);
    QVBoxLayout *sidebarLay = new QVBoxLayout(m_sidebar);
    sidebarLay->setContentsMargins(0, 0, 0, 0);
    sidebarLay->setSpacing(0);

    // Logo区
    QWidget *logoArea = new QWidget;
    logoArea->setObjectName("logoArea");
    logoArea->setFixedHeight(64);
    QHBoxLayout *logoLay = new QHBoxLayout(logoArea);
    logoLay->setContentsMargins(12, 8, 12, 8);
    QLabel *logoIcon = new QLabel;
    logoIcon->setPixmap(IconHelper::pixmap("app", 36));
    logoIcon->setFixedSize(36, 36);
    QVBoxLayout *logoTextLay = new QVBoxLayout;
    logoTextLay->setSpacing(2);
    QLabel *logoTitle = new QLabel("恶意代码检测");
    logoTitle->setObjectName("logoTitle");
    QLabel *logoSub = new QLabel("辅助检测系统 V3.0");
    logoSub->setObjectName("logoSub");
    logoTextLay->addWidget(logoTitle);
    logoTextLay->addWidget(logoSub);
    logoLay->addWidget(logoIcon);
    logoLay->addSpacing(8);
    logoLay->addLayout(logoTextLay);
    sidebarLay->addWidget(logoArea);

    // 用户信息区
    QWidget *userArea = new QWidget;
    userArea->setObjectName("userArea");
    userArea->setFixedHeight(52);
    QHBoxLayout *userLay = new QHBoxLayout(userArea);
    userLay->setContentsMargins(12, 4, 8, 4);
    QLabel *userIcon = new QLabel;
    QString userIconName = (m_role=="system_admin") ? "user_admin" :
                           (m_role=="sec_admin")    ? "user_secadmin" : "user_auditor";
    userIcon->setPixmap(IconHelper::pixmap(userIconName, 24));
    userIcon->setFixedSize(24, 24);
    m_lblUser = new QLabel(m_username + "\n" +
        (m_role=="system_admin"?"系统管理员":m_role=="sec_admin"?"安全管理员":"安全审计员"));
    m_lblUser->setObjectName("userLabel");
    m_btnLogout = new QPushButton;
    m_btnLogout->setIcon(IconHelper::btnLogout());
    m_btnLogout->setIconSize(QSize(14,14));
    m_btnLogout->setObjectName("btnLogout");
    m_btnLogout->setFixedSize(28, 28);
    m_btnLogout->setToolTip("退出登录");
    connect(m_btnLogout, &QPushButton::clicked, this, &MainWindow::onLogout);
    userLay->addWidget(userIcon);
    userLay->addSpacing(6);
    userLay->addWidget(m_lblUser, 1);
    userLay->addWidget(m_btnLogout);
    sidebarLay->addWidget(userArea);

    // 导航树
    m_navTree = new QTreeWidget;
    m_navTree->setObjectName("navTree");
    m_navTree->setHeaderHidden(true);
    m_navTree->setRootIsDecorated(true);
    m_navTree->setIndentation(16);
    m_navTree->setIconSize(QSize(18, 18));
    m_navTree->setExpandsOnDoubleClick(false);
    connect(m_navTree, &QTreeWidget::itemClicked, this, &MainWindow::onNavItemClicked);
    sidebarLay->addWidget(m_navTree, 1);

    // 病毒库版本
    m_lblVirusDb = new QLabel("病毒库：" + DatabaseManager::instance()->getSetting("virus_db_version","20251120"));
    m_lblVirusDb->setObjectName("virusDbLabel");
    m_lblVirusDb->setAlignment(Qt::AlignCenter);
    sidebarLay->addWidget(m_lblVirusDb);

    mainLay->addWidget(m_sidebar);

    // 分割线
    QFrame *vline = new QFrame;
    vline->setFrameShape(QFrame::VLine);
    vline->setObjectName("vDivider");
    mainLay->addWidget(vline);

    // ── 右侧内容区 ──────────────────────────────────────────
    QWidget *contentArea = new QWidget;
    contentArea->setObjectName("contentArea");
    QVBoxLayout *contentLay = new QVBoxLayout(contentArea);
    contentLay->setContentsMargins(0, 0, 0, 0);
    contentLay->setSpacing(0);

    m_stack = new QStackedWidget;
    m_stack->setObjectName("mainStack");
    contentLay->addWidget(m_stack, 1);

    statusBar()->setObjectName("statusBar");
    statusBar()->showMessage("就绪  |  " + QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss"));
    mainLay->addWidget(contentArea, 1);
}

void MainWindow::setupNav()
{
    // ── 系统概览（顶级，一级菜单）──
    QTreeWidgetItem *dash = new QTreeWidgetItem(m_navTree);
    dash->setText(0, "  系统概览");
    dash->setIcon(0, IconHelper::navDashboard());
    dash->setData(0, Qt::UserRole, 0);

    // ── 基础信息 ──
    QTreeWidgetItem *grpInfo = new QTreeWidgetItem(m_navTree);
    grpInfo->setText(0, "  基础信息");
    grpInfo->setIcon(0, IconHelper::groupCollect());
    grpInfo->setData(0, Qt::UserRole, -1);
    grpInfo->setExpanded(true);
    addNavItem(grpInfo, IconHelper::navSysInfo(),   "系统信息",   1);
    addNavItem(grpInfo, IconHelper::navNetwork(),   "网络连接",   2);
    addNavItem(grpInfo, IconHelper::navDisk(),      "硬盘信息",   3);
    addNavItem(grpInfo, IconHelper::navProcess(),   "进程列表",   4);
    addNavItem(grpInfo, IconHelper::navPort(),      "端口监听",   5);
    addNavItem(grpInfo, IconHelper::navAutorun(),   "自启动项",   6);
    addNavItem(grpInfo, IconHelper::navScheduled(), "计划任务",   7);
    addNavItem(grpInfo, IconHelper::navDriver(),    "驱动信息",   8);
    addNavItem(grpInfo, IconHelper::navShared(),    "共享资源",   9);
    addNavItem(grpInfo, IconHelper::navPlugin(),    "插件分析",  10);
    addNavItem(grpInfo, IconHelper::navMemory(),    "内存映像",  11);

    // ── 检测分析 ──
    QTreeWidgetItem *grpScan = new QTreeWidgetItem(m_navTree);
    grpScan->setText(0, "  检测分析");
    grpScan->setIcon(0, IconHelper::groupScan());
    grpScan->setData(0, Qt::UserRole, -1);
    grpScan->setExpanded(true);
    addNavItem(grpScan, IconHelper::navStatic(),  "静态检测", 12);
    addNavItem(grpScan, IconHelper::navDynamic(), "动态监测", 13);

    // ── 综合分析 ──
    QTreeWidgetItem *grpAnalysis = new QTreeWidgetItem(m_navTree);
    grpAnalysis->setText(0, "  综合分析");
    grpAnalysis->setIcon(0, IconHelper::icon("group_analysis"));
    grpAnalysis->setData(0, Qt::UserRole, -1);
    grpAnalysis->setExpanded(true);
    addNavItem(grpAnalysis, IconHelper::icon("nav_search"),    "全局搜索", 14);
    addNavItem(grpAnalysis, IconHelper::navSample(),           "样本提取", 15);
    addNavItem(grpAnalysis, IconHelper::icon("nav_vuln"),      "漏洞监测", 16);
    addNavItem(grpAnalysis, IconHelper::navReport(),           "检测报告", 17);

    // ── 系统管理 ──
    QTreeWidgetItem *grpMgmt = new QTreeWidgetItem(m_navTree);
    grpMgmt->setText(0, "  系统管理");
    grpMgmt->setIcon(0, IconHelper::groupResult());
    grpMgmt->setData(0, Qt::UserRole, -1);
    grpMgmt->setExpanded(true);
    addNavItem(grpMgmt, IconHelper::navLog(),                  "日志审计", 18);
    addNavItem(grpMgmt, IconHelper::icon("nav_usermgr"),       "用户管理", 19);
    addNavItem(grpMgmt, IconHelper::navSettings(),             "系统设置", 20);

    m_navTree->setCurrentItem(dash);
}

QTreeWidgetItem* MainWindow::addNavItem(QTreeWidgetItem *parent,
                                         const QIcon &icon,
                                         const QString &text,
                                         int pageIndex)
{
    QTreeWidgetItem *item = new QTreeWidgetItem(parent);
    item->setText(0, "  " + text);
    item->setIcon(0, icon);
    item->setData(0, Qt::UserRole, pageIndex);
    return item;
}

void MainWindow::setupPages()
{
    m_pgDashboard    = new DashboardPage;
    m_pgSysInfo      = new SystemInfoPage;
    m_pgNetInfo      = new NetworkInfoPage;
    m_pgDiskInfo     = new DiskInfoPage;
    m_pgProcess      = new ProcessInfoPage;
    m_pgPort         = new PortInfoPage;
    m_pgAutorun      = new AutorunPage;
    m_pgScheduled    = new ScheduledTaskPage;
    m_pgDriver       = new DriverInfoPage;
    m_pgShared       = new SharedResourcePage;
    m_pgBrowser      = new BrowserPluginPage;
    m_pgMemory       = new MemoryImagePage;
    m_pgStatic       = new StaticScanPage;
    m_pgDynamic      = new DynamicScanPage;
    m_pgGlobalSearch = new GlobalSearchPage;
    m_pgSample       = new SampleExtractPage;
    m_pgVulnDetect   = new VulnDetectPage;
    m_pgReport       = new ReportPage;
    m_pgLog          = new LogAuditPage;
    m_pgUserManage   = new UserManagePage;
    m_pgSettings     = new SystemSettingsPage;

    m_stack->addWidget(m_pgDashboard);    // 0
    m_stack->addWidget(m_pgSysInfo);      // 1
    m_stack->addWidget(m_pgNetInfo);      // 2
    m_stack->addWidget(m_pgDiskInfo);     // 3
    m_stack->addWidget(m_pgProcess);      // 4
    m_stack->addWidget(m_pgPort);         // 5
    m_stack->addWidget(m_pgAutorun);      // 6
    m_stack->addWidget(m_pgScheduled);    // 7
    m_stack->addWidget(m_pgDriver);       // 8
    m_stack->addWidget(m_pgShared);       // 9
    m_stack->addWidget(m_pgBrowser);      // 10
    m_stack->addWidget(m_pgMemory);       // 11
    m_stack->addWidget(m_pgStatic);       // 12
    m_stack->addWidget(m_pgDynamic);      // 13
    m_stack->addWidget(m_pgGlobalSearch); // 14
    m_stack->addWidget(m_pgSample);       // 15
    m_stack->addWidget(m_pgVulnDetect);   // 16
    m_stack->addWidget(m_pgReport);       // 17
    m_stack->addWidget(m_pgLog);          // 18
    m_stack->addWidget(m_pgUserManage);   // 19
    m_stack->addWidget(m_pgSettings);     // 20
}

void MainWindow::switchPage(int index)
{
    if (index < 0 || index >= m_stack->count()) return;
    m_stack->setCurrentIndex(index);
    m_currentPageIdx = index;
    statusBar()->showMessage("就绪  |  " + QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss"));
}

void MainWindow::onNavItemClicked(QTreeWidgetItem *item, int)
{
    if (!item) return;
    int idx = item->data(0, Qt::UserRole).toInt();
    if (idx < 0) {
        item->setExpanded(!item->isExpanded());
        return;
    }
    switchPage(idx);
}

void MainWindow::onLogout()
{
    DatabaseManager::instance()->writeLog(m_role, m_username, "用户退出", "正常退出", "success");
    QApplication::quit();
}

void MainWindow::onRefreshCurrentPage()
{
    if (auto *p = qobject_cast<BasePage*>(m_stack->currentWidget()))
        p->refreshData();
}

void MainWindow::applyStyle()
{
    // 全局主题已在 main.cpp 中通过 StyleManager::applyGlobal() 加载
}
