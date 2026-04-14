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
#include "pages/FileAssocPage.h"
#include "pages/SampleExtractPage.h"
#include "pages/ReportPage.h"
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
    setLoader(m_pgDashboard);  setLoader(m_pgSysInfo);   setLoader(m_pgNetInfo);
    setLoader(m_pgDiskInfo);   setLoader(m_pgProcess);   setLoader(m_pgPort);
    setLoader(m_pgAutorun);    setLoader(m_pgScheduled); setLoader(m_pgDriver);
    setLoader(m_pgShared);     setLoader(m_pgBrowser);   setLoader(m_pgMemory);
    setLoader(m_pgStatic);     setLoader(m_pgDynamic);
    setLoader(m_pgFileAssoc);  setLoader(m_pgSample);    setLoader(m_pgReport);
    setLoader(m_pgLog);        setLoader(m_pgSettings);
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

    // Logo区 - 使用 app 图标图片
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

    // 用户信息区 - 使用角色对应图标
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
    // ── 系统概览（顶级）──
    QTreeWidgetItem *dash = new QTreeWidgetItem(m_navTree);
    dash->setText(0, "  系统概览");
    dash->setIcon(0, IconHelper::navDashboard());
    dash->setData(0, Qt::UserRole, 0);

    // ── 系统信息采集 ──
    QTreeWidgetItem *grpInfo = new QTreeWidgetItem(m_navTree);
    grpInfo->setText(0, "  系统信息采集");
    grpInfo->setIcon(0, IconHelper::groupCollect());
    grpInfo->setData(0, Qt::UserRole, -1);
    grpInfo->setExpanded(true);
    addNavItem(grpInfo, IconHelper::navSysInfo(),   "系统基本信息", 1);
    addNavItem(grpInfo, IconHelper::navNetwork(),   "网络信息",     2);
    addNavItem(grpInfo, IconHelper::navDisk(),      "硬盘信息",     3);
    addNavItem(grpInfo, IconHelper::navProcess(),   "进程信息",     4);
    addNavItem(grpInfo, IconHelper::navPort(),      "端口信息",     5);
    addNavItem(grpInfo, IconHelper::navAutorun(),   "自启动项",     6);
    addNavItem(grpInfo, IconHelper::navScheduled(), "计划任务",     7);
    addNavItem(grpInfo, IconHelper::navDriver(),    "驱动信息",     8);
    addNavItem(grpInfo, IconHelper::navShared(),    "共享资源",     9);
    addNavItem(grpInfo, IconHelper::navPlugin(),    "浏览器插件",  10);
    addNavItem(grpInfo, IconHelper::navMemory(),    "内存映像",    11);

    // ── 检测分析 ──
    QTreeWidgetItem *grpScan = new QTreeWidgetItem(m_navTree);
    grpScan->setText(0, "  检测分析");
    grpScan->setIcon(0, IconHelper::groupScan());
    grpScan->setData(0, Qt::UserRole, -1);
    grpScan->setExpanded(true);
    addNavItem(grpScan, IconHelper::navStatic(),    "静态检测",     12);
    addNavItem(grpScan, IconHelper::navDynamic(),   "动态行为检测", 13);
    // 数字证书检测已合并至静态检测模块 Tab，不再独立显示
    addNavItem(grpScan, IconHelper::navFileAssoc(), "文件关联检测", 14);
    addNavItem(grpScan, IconHelper::navSample(),    "样本提取",     15);

    // ── 结果管理 ──
    QTreeWidgetItem *grpResult = new QTreeWidgetItem(m_navTree);
    grpResult->setText(0, "  结果管理");
    grpResult->setIcon(0, IconHelper::groupResult());
    grpResult->setData(0, Qt::UserRole, -1);
    grpResult->setExpanded(true);
    addNavItem(grpResult, IconHelper::navReport(),   "检测报告", 16);
    addNavItem(grpResult, IconHelper::navLog(),      "日志审计", 17);
    addNavItem(grpResult, IconHelper::navSettings(), "系统设置", 18);

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
    m_pgDashboard = new DashboardPage;
    m_pgSysInfo   = new SystemInfoPage;
    m_pgNetInfo   = new NetworkInfoPage;
    m_pgDiskInfo  = new DiskInfoPage;
    m_pgProcess   = new ProcessInfoPage;
    m_pgPort      = new PortInfoPage;
    m_pgAutorun   = new AutorunPage;
    m_pgScheduled = new ScheduledTaskPage;
    m_pgDriver    = new DriverInfoPage;
    m_pgShared    = new SharedResourcePage;
    m_pgBrowser   = new BrowserPluginPage;
    m_pgMemory    = new MemoryImagePage;
    m_pgStatic    = new StaticScanPage;
    m_pgDynamic   = new DynamicScanPage;
    // m_pgCert 已删除：数字证书检测已合并至 StaticScanPage 的证书 Tab
    m_pgFileAssoc = new FileAssocPage;
    m_pgSample    = new SampleExtractPage;
    m_pgReport    = new ReportPage;
    m_pgLog       = new LogAuditPage;
    m_pgSettings  = new SystemSettingsPage;

    m_stack->addWidget(m_pgDashboard); // 0
    m_stack->addWidget(m_pgSysInfo);   // 1
    m_stack->addWidget(m_pgNetInfo);   // 2
    m_stack->addWidget(m_pgDiskInfo);  // 3
    m_stack->addWidget(m_pgProcess);   // 4
    m_stack->addWidget(m_pgPort);      // 5
    m_stack->addWidget(m_pgAutorun);   // 6
    m_stack->addWidget(m_pgScheduled); // 7
    m_stack->addWidget(m_pgDriver);    // 8
    m_stack->addWidget(m_pgShared);    // 9
    m_stack->addWidget(m_pgBrowser);   // 10
    m_stack->addWidget(m_pgMemory);    // 11
    m_stack->addWidget(m_pgStatic);    // 12
    m_stack->addWidget(m_pgDynamic);   // 13
    // 14 原数字证书已合并至静态检测，跳过
    m_stack->addWidget(m_pgFileAssoc); // 14
    m_stack->addWidget(m_pgSample);    // 15
    m_stack->addWidget(m_pgReport);    // 16
    m_stack->addWidget(m_pgLog);       // 17
    m_stack->addWidget(m_pgSettings);  // 18
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
    setStyleSheet(R"(
        QMainWindow, QWidget {
            background: #0d1b2e;
            color: #e0e0e0;
            font-family: "Microsoft YaHei", "SimHei", "WenQuanYi Micro Hei", sans-serif;
            font-size: 13px;
        }
        #sidebar { background: #0a1628; }
        #logoArea { background: #0d2240; }
        #logoTitle { color: #ffffff; font-size: 13px; font-weight: bold; }
        #logoSub   { color: #4fc3f7; font-size: 10px; }
        #userArea  { background: #0a1e38; }
        #userLabel { color: #90caf9; font-size: 11px; }
        #btnLogout {
            background: transparent; color: #ef5350;
            border: 1px solid #ef5350; border-radius: 3px;
        }
        #btnLogout:hover { background: #ef5350; }
        #virusDbLabel { color: #546e7a; font-size: 10px; padding: 6px; }
        #navTree {
            background: #0a1628; border: none; outline: none;
        }
        #navTree::item {
            height: 32px; padding-left: 2px; color: #90caf9;
        }
        #navTree::item:selected {
            background: #1565c0; color: #ffffff;
        }
        #navTree::item:hover:!selected { background: #1a2a3e; }
        #navTree::branch { background: #0a1628; }
        #contentArea { background: #0d1b2e; }
        #mainStack   { background: #0d1b2e; }
        #vDivider    { color: #1a2a3e; }
        #pageTitle { font-size: 16px; font-weight: bold; color: #4fc3f7; }
        #pageStatus { color: #546e7a; font-size: 11px; }
        #sectionLabel { color: #90caf9; font-size: 12px; font-weight: bold; padding: 4px 0; }
        #divider { color: #1a2a3e; }
        #btnPrimary {
            background: #1565c0; color: #fff; border: none;
            border-radius: 3px; padding: 5px 14px;
        }
        #btnPrimary:hover   { background: #1976d2; }
        #btnPrimary:pressed { background: #0d47a1; }
        #btnSecondary {
            background: #1a2a3e; color: #90caf9;
            border: 1px solid #2a4a6e; border-radius: 3px; padding: 5px 14px;
        }
        #btnSecondary:hover { background: #1e3a5a; }
        #btnWarning {
            background: #b71c1c; color: #fff; border: none;
            border-radius: 3px; padding: 5px 14px;
        }
        #btnWarning:hover { background: #c62828; }
        #btnRefresh, #btnSmall {
            background: #1a2a3e; color: #90caf9;
            border: 1px solid #2a4a6e; border-radius: 3px; padding: 3px 8px;
        }
        #btnRefresh:hover, #btnSmall:hover { background: #1e3a5a; }
        QTableWidget {
            background: #0d1b2e;
            alternate-background-color: #0f2035;
            gridline-color: #1a2a3e;
            border: 1px solid #1a2a3e;
            color: #e0e0e0;
            selection-background-color: #1565c0;
            selection-color: #ffffff;
        }
        QTableWidget::item { padding: 4px 6px; }
        QHeaderView::section {
            background: #1a2a3e; color: #90caf9;
            border: none; border-right: 1px solid #0d1b2e;
            padding: 5px 6px; font-weight: bold;
        }
        QScrollBar:vertical {
            background: #0a1628; width: 8px; border: none;
        }
        QScrollBar::handle:vertical {
            background: #2a4a6e; border-radius: 4px; min-height: 20px;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        QScrollBar:horizontal {
            background: #0a1628; height: 8px; border: none;
        }
        QScrollBar::handle:horizontal {
            background: #2a4a6e; border-radius: 4px; min-width: 20px;
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
        #searchInput, #loginInput, #settingsInput {
            background: #1a2a3e; border: 1px solid #2a4a6e;
            border-radius: 3px; color: #e0e0e0; padding: 5px 10px;
        }
        #searchInput:focus, #settingsInput:focus { border: 1px solid #1976d2; }
        QTabWidget::pane { border: 1px solid #1a2a3e; background: #0d1b2e; }
        QTabBar::tab {
            background: #1a2a3e; color: #90caf9;
            padding: 6px 16px; border: none; border-bottom: 2px solid transparent;
        }
        QTabBar::tab:selected {
            background: #0d1b2e; color: #4fc3f7;
            border-bottom: 2px solid #1976d2;
        }
        QTabBar::tab:hover:!selected { background: #1e3a5a; }
        #codeView, #reportView {
            background: #0a1628; color: #b0bec5;
            border: 1px solid #1a2a3e;
            font-family: Consolas, "Courier New", monospace; font-size: 12px;
        }
        QComboBox, #comboBox {
            background: #1a2a3e; color: #e0e0e0;
            border: 1px solid #2a4a6e; border-radius: 3px; padding: 4px 8px;
        }
        QComboBox::drop-down { border: none; }
        QComboBox QAbstractItemView {
            background: #1a2a3e; color: #e0e0e0;
            selection-background-color: #1565c0;
        }
        QDateEdit, #dateEdit {
            background: #1a2a3e; color: #e0e0e0;
            border: 1px solid #2a4a6e; border-radius: 3px; padding: 4px 8px;
        }
        #settingsNav {
            background: #0a1628; border: none; border-right: 1px solid #1a2a3e;
        }
        #settingsNav::item { height: 36px; padding-left: 12px; color: #90caf9; }
        #settingsNav::item:selected { background: #1565c0; color: #fff; }
        #settingsStack { background: #0d1b2e; padding: 12px; }
        QGroupBox#settingsGroup {
            border: 1px solid #1a2a3e; border-radius: 4px;
            margin-top: 8px; padding-top: 8px; color: #90caf9;
        }
        QGroupBox#settingsGroup::title { subcontrol-origin: margin; left: 12px; color: #4fc3f7; }
        QGroupBox#dashGroup {
            border: 1px solid #1a2a3e; border-radius: 4px;
            margin-top: 8px; padding-top: 8px;
        }
        QGroupBox#dashGroup::title { subcontrol-origin: margin; left: 12px; color: #4fc3f7; }
        QCheckBox { color: #e0e0e0; }
        QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid #2a4a6e; background: #1a2a3e; }
        QCheckBox::indicator:checked { background: #1565c0; border: 1px solid #1976d2; }
        QSpinBox, #spinBox {
            background: #1a2a3e; color: #e0e0e0;
            border: 1px solid #2a4a6e; border-radius: 3px; padding: 4px 8px;
        }
        #processTree {
            background: #0a1628; border: 1px solid #1a2a3e; color: #e0e0e0;
        }
        #processTree::item { height: 24px; }
        #processTree::item:selected { background: #1565c0; }
        #kvKey { color: #90caf9; font-size: 12px; }
        #kvVal { color: #e0e0e0; font-size: 12px; }
        QStatusBar { background: #0a1628; color: #546e7a; font-size: 11px; }
        #conclusionLabel { color: #e0e0e0; font-size: 13px; padding: 8px; }
        #infoLabel { color: #546e7a; font-size: 11px; }
        #aboutLabel { color: #e0e0e0; padding: 12px; }
        #fieldLabel { color: #90caf9; font-size: 12px; }
        #btnQuickStatic, #btnQuickDynamic, #btnQuickReport {
            background: #1a2a3e; color: #90caf9;
            border: 1px solid #2a4a6e; border-radius: 3px; padding: 4px 16px;
        }
        #btnQuickStatic:hover, #btnQuickDynamic:hover, #btnQuickReport:hover {
            background: #1565c0; color: #fff;
        }
    )");
}
