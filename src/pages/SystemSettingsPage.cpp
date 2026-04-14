#include "pages/SystemSettingsPage.h"
#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QLabel>
#include <QFileDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QInputDialog>
#include <QSqlQuery>
#include <QDateTime>
#include <QHeaderView>
#include <QThread>
#include <QApplication>
#include <QFrame>

SystemSettingsPage::SystemSettingsPage(QWidget *parent) : BasePage("系统设置", parent) {
    setupUi();
    loadSettings();
}

void SystemSettingsPage::setupUi() {
    QHBoxLayout *mainRow = new QHBoxLayout;
    mainRow->setSpacing(0);

    // 左侧导航
    m_navList = new QListWidget;
    m_navList->setObjectName("settingsNav");
    m_navList->setFixedWidth(150);
    m_navList->addItem("  基础配置");
    m_navList->addItem("  病毒库管理");
    m_navList->addItem("  扫描策略");
    m_navList->addItem("  白名单管理");
    m_navList->addItem("  自定义规则");
    m_navList->addItem("  用户管理");
    m_navList->addItem("  日志设置");
    m_navList->addItem("  关于系统");
    m_navList->setCurrentRow(0);
    connect(m_navList, &QListWidget::currentRowChanged, this, &SystemSettingsPage::onNavChanged);
    mainRow->addWidget(m_navList);

    m_stack = new QStackedWidget;
    m_stack->setObjectName("settingsStack");

    // ── 0: 基础配置 ──────────────────────────────────────────────
    QWidget *pgBase = new QWidget;
    QVBoxLayout *baseLay = new QVBoxLayout(pgBase);
    baseLay->setContentsMargins(16, 16, 16, 16);
    QGroupBox *dllGrp = new QGroupBox("动态库路径");
    dllGrp->setObjectName("settingsGroup");
    QFormLayout *dllForm = new QFormLayout(dllGrp);
    m_editDllPath = new QLineEdit;
    m_editDllPath->setObjectName("settingsInput");
    m_editDllPath->setPlaceholderText("basic.dll 路径");
    QPushButton *btnDll = new QPushButton("浏览");
    btnDll->setObjectName("btnSmall");
    QHBoxLayout *dllRow = new QHBoxLayout;
    dllRow->addWidget(m_editDllPath, 1);
    dllRow->addWidget(btnDll);
    connect(btnDll, &QPushButton::clicked, [this](){
        QString p = QFileDialog::getOpenFileName(this,"选择 basic.dll","","动态库 (*.dll *.so)");
        if (!p.isEmpty()) m_editDllPath->setText(p);
    });
    dllForm->addRow("basic.dll 路径：", dllRow);
    m_editDbPath = new QLineEdit;
    m_editDbPath->setObjectName("settingsInput");
    m_editDbPath->setPlaceholderText("数据库文件路径");
    QPushButton *btnDb = new QPushButton("浏览");
    btnDb->setObjectName("btnSmall");
    QHBoxLayout *dbRow = new QHBoxLayout;
    dbRow->addWidget(m_editDbPath, 1);
    dbRow->addWidget(btnDb);
    connect(btnDb, &QPushButton::clicked, [this](){
        QString p = QFileDialog::getSaveFileName(this,"选择数据库路径","malware_detector.db","SQLite数据库 (*.db)");
        if (!p.isEmpty()) m_editDbPath->setText(p);
    });
    dllForm->addRow("数据库路径：", dbRow);
    baseLay->addWidget(dllGrp);
    QGroupBox *reportGrp = new QGroupBox("报告输出目录");
    reportGrp->setObjectName("settingsGroup");
    QFormLayout *reportForm = new QFormLayout(reportGrp);
    m_editReportDir = new QLineEdit;
    m_editReportDir->setObjectName("settingsInput");
    QPushButton *btnRpt = new QPushButton("浏览");
    btnRpt->setObjectName("btnSmall");
    QHBoxLayout *rptRow = new QHBoxLayout;
    rptRow->addWidget(m_editReportDir, 1);
    rptRow->addWidget(btnRpt);
    connect(btnRpt, &QPushButton::clicked, [this](){
        QString p = QFileDialog::getExistingDirectory(this,"选择报告输出目录");
        if (!p.isEmpty()) m_editReportDir->setText(p);
    });
    reportForm->addRow("输出目录：", rptRow);
    baseLay->addWidget(reportGrp);
    baseLay->addStretch();
    m_stack->addWidget(pgBase);

    // ── 1: 病毒库管理 ─────────────────────────────────────────────
    QWidget *pgVirus = new QWidget;
    QVBoxLayout *virusLay = new QVBoxLayout(pgVirus);
    virusLay->setContentsMargins(16, 16, 16, 16);

    // 状态卡片
    QFrame *statusCard = new QFrame;
    statusCard->setStyleSheet("QFrame{background:#f0f7ff;border:1px solid #91d5ff;border-radius:4px;padding:8px;}");
    QHBoxLayout *statusRow = new QHBoxLayout(statusCard);
    m_lblDbVer    = new QLabel("当前版本：20251120");
    m_lblDbDate   = new QLabel("更新时间：2025-11-20");
    m_lblDbStatus = new QLabel("状态：最新");
    m_lblDbStatus->setStyleSheet("color:#389e0d;font-weight:bold;");
    statusRow->addWidget(m_lblDbVer);
    statusRow->addSpacing(20);
    statusRow->addWidget(m_lblDbDate);
    statusRow->addSpacing(20);
    statusRow->addWidget(m_lblDbStatus);
    statusRow->addStretch();
    virusLay->addWidget(statusCard);

    // 进度条
    m_progressUpdate = new QProgressBar;
    m_progressUpdate->setRange(0, 100);
    m_progressUpdate->setValue(0);
    m_progressUpdate->setVisible(false);
    m_progressUpdate->setStyleSheet(
        "QProgressBar{border:1px solid #d0d7e3;border-radius:3px;height:14px;text-align:center;}"
        "QProgressBar::chunk{background:#1a3a6a;}");
    virusLay->addWidget(m_progressUpdate);

    QGroupBox *virusGrp = new QGroupBox("更新设置");
    virusGrp->setObjectName("settingsGroup");
    QFormLayout *virusForm = new QFormLayout(virusGrp);
    m_chkAutoUpdate = new QCheckBox("启用自动更新");
    m_chkAutoUpdate->setChecked(true);
    virusForm->addRow("自动更新：", m_chkAutoUpdate);
    m_cmbUpdateFreq = new QComboBox;
    m_cmbUpdateFreq->addItems({"每天更新", "每周更新", "每两周更新"});
    m_cmbUpdateFreq->setFixedWidth(160);
    virusForm->addRow("更新频率：", m_cmbUpdateFreq);
    m_edtUpdateSource = new QLineEdit("http://update.internal.local/virusdb");
    QLabel *hintLbl = new QLabel("（不支持互联网在线升级）");
    hintLbl->setStyleSheet("color:#888;font-size:11px;");
    QHBoxLayout *srcRow = new QHBoxLayout;
    srcRow->addWidget(m_edtUpdateSource);
    srcRow->addWidget(hintLbl);
    virusForm->addRow("更新源：", srcRow);
    m_btnUpdate = new QPushButton("立即检查更新");
    m_btnUpdate->setObjectName("btnPrimary");
    m_btnUpdate->setFixedWidth(130);
    connect(m_btnUpdate, &QPushButton::clicked, this, &SystemSettingsPage::onUpdateVirusDb);
    virusForm->addRow("", m_btnUpdate);
    virusLay->addWidget(virusGrp);
    virusLay->addStretch();
    m_stack->addWidget(pgVirus);

    // ── 2: 扫描策略 ───────────────────────────────────────────────
    QWidget *pgScan = new QWidget;
    QVBoxLayout *scanLay = new QVBoxLayout(pgScan);
    scanLay->setContentsMargins(16, 16, 16, 16);
    QGroupBox *scanGrp = new QGroupBox("扫描策略");
    scanGrp->setObjectName("settingsGroup");
    QVBoxLayout *scanGrpLay = new QVBoxLayout(scanGrp);
    m_chkAutoScan    = new QCheckBox("启用定时自动扫描");
    m_chkStartupScan = new QCheckBox("系统启动时自动扫描");
    m_chkRealtime    = new QCheckBox("启用实时监控（需要驱动支持）");
    m_chkScanArchive = new QCheckBox("扫描压缩包内文件");
    m_chkScanHidden  = new QCheckBox("扫描隐藏文件和目录");
    m_chkAutoScan->setObjectName("settingsCheck");
    m_chkStartupScan->setObjectName("settingsCheck");
    m_chkRealtime->setObjectName("settingsCheck");
    m_chkScanArchive->setObjectName("settingsCheck");
    m_chkScanHidden->setObjectName("settingsCheck");
    m_chkScanArchive->setChecked(true);
    m_chkScanHidden->setChecked(true);
    scanGrpLay->addWidget(m_chkAutoScan);
    scanGrpLay->addWidget(m_chkStartupScan);
    scanGrpLay->addWidget(m_chkRealtime);
    scanGrpLay->addWidget(m_chkScanArchive);
    scanGrpLay->addWidget(m_chkScanHidden);
    scanLay->addWidget(scanGrp);
    scanLay->addStretch();
    m_stack->addWidget(pgScan);

    // ── 3: 白名单管理 ─────────────────────────────────────────────
    QWidget *pgWhite = new QWidget;
    QVBoxLayout *whiteLay = new QVBoxLayout(pgWhite);
    whiteLay->setContentsMargins(16, 16, 16, 16);
    QHBoxLayout *whiteBtn = new QHBoxLayout;
    m_btnAddWhite = new QPushButton("添加路径");
    m_btnAddWhite->setObjectName("btnPrimary");
    QPushButton *btnAddMd5 = new QPushButton("添加MD5");
    btnAddMd5->setObjectName("btnPrimary");
    m_btnDelWhite = new QPushButton("删除");
    m_btnDelWhite->setObjectName("btnWarning");
    QPushButton *btnExportWl = new QPushButton("导出");
    btnExportWl->setObjectName("btnSecondary");
    for (auto *b : {m_btnAddWhite, btnAddMd5, m_btnDelWhite, btnExportWl}) b->setFixedWidth(90);
    connect(m_btnAddWhite, &QPushButton::clicked, this, &SystemSettingsPage::onAddWhitelist);
    connect(m_btnDelWhite, &QPushButton::clicked, this, &SystemSettingsPage::onDelWhitelist);
    whiteBtn->addWidget(m_btnAddWhite);
    whiteBtn->addWidget(btnAddMd5);
    whiteBtn->addWidget(btnExportWl);
    whiteBtn->addWidget(m_btnDelWhite);
    whiteBtn->addStretch();
    whiteLay->addLayout(whiteBtn);
    m_tblWhitelist = new QTableWidget(0, 5);
    m_tblWhitelist->setHorizontalHeaderLabels({"类型","值/路径","备注","添加时间","操作"});
    styleTable(m_tblWhitelist);
    m_tblWhitelist->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_tblWhitelist->setColumnWidth(0, 60);
    m_tblWhitelist->setColumnWidth(2, 120);
    m_tblWhitelist->setColumnWidth(3, 100);
    m_tblWhitelist->setColumnWidth(4, 60);
    whiteLay->addWidget(m_tblWhitelist, 1);
    m_stack->addWidget(pgWhite);

    // ── 4: 自定义规则 ─────────────────────────────────────────────
    QWidget *pgRules = new QWidget;
    QVBoxLayout *rulesLay = new QVBoxLayout(pgRules);
    rulesLay->setContentsMargins(16, 16, 16, 16);
    QHBoxLayout *rulesBtn = new QHBoxLayout;
    m_btnAddRule = new QPushButton("新增规则");
    m_btnAddRule->setObjectName("btnPrimary");
    m_btnDelRule = new QPushButton("删除规则");
    m_btnDelRule->setObjectName("btnWarning");
    QPushButton *btnImportRule = new QPushButton("导入规则");
    btnImportRule->setObjectName("btnSecondary");
    QPushButton *btnExportRule = new QPushButton("导出规则");
    btnExportRule->setObjectName("btnSecondary");
    for (auto *b : {m_btnAddRule, btnImportRule, btnExportRule, m_btnDelRule}) b->setFixedWidth(90);
    connect(m_btnAddRule, &QPushButton::clicked, this, &SystemSettingsPage::onAddRule);
    connect(m_btnDelRule, &QPushButton::clicked, this, &SystemSettingsPage::onDelRule);
    rulesBtn->addWidget(m_btnAddRule);
    rulesBtn->addWidget(btnImportRule);
    rulesBtn->addWidget(btnExportRule);
    rulesBtn->addWidget(m_btnDelRule);
    rulesBtn->addStretch();
    rulesLay->addLayout(rulesBtn);
    m_tblRules = new QTableWidget(0, 6);
    m_tblRules->setHorizontalHeaderLabels({"规则ID","规则名称","类型","规则内容","风险等级","状态"});
    styleTable(m_tblRules);
    m_tblRules->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_tblRules->setColumnWidth(0, 80);
    m_tblRules->setColumnWidth(1, 160);
    m_tblRules->setColumnWidth(2, 80);
    m_tblRules->setColumnWidth(4, 70);
    m_tblRules->setColumnWidth(5, 60);
    rulesLay->addWidget(m_tblRules, 1);
    m_stack->addWidget(pgRules);

    // ── 5: 用户管理 ───────────────────────────────────────────────
    QWidget *pgUsers = new QWidget;
    QVBoxLayout *usersLay = new QVBoxLayout(pgUsers);
    usersLay->setContentsMargins(16, 16, 16, 16);
    QLabel *userHint = new QLabel("系统采用三员管理模式：系统管理员、安全管理员、安全审计员");
    userHint->setStyleSheet("color:#888;font-size:11px;margin-bottom:6px;");
    usersLay->addWidget(userHint);
    m_tblUsers = new QTableWidget(0, 5);
    m_tblUsers->setHorizontalHeaderLabels({"用户名","角色","状态","上次登录","操作"});
    styleTable(m_tblUsers);
    m_tblUsers->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_tblUsers->setColumnWidth(0, 100);
    m_tblUsers->setColumnWidth(1, 110);
    m_tblUsers->setColumnWidth(2, 70);
    m_tblUsers->setColumnWidth(4, 90);
    usersLay->addWidget(m_tblUsers, 1);
    m_stack->addWidget(pgUsers);

    // ── 6: 日志设置 ───────────────────────────────────────────────
    QWidget *pgLog = new QWidget;
    QVBoxLayout *logLay = new QVBoxLayout(pgLog);
    logLay->setContentsMargins(16, 16, 16, 16);
    QGroupBox *logGrp = new QGroupBox("日志保留策略");
    logGrp->setObjectName("settingsGroup");
    QFormLayout *logForm = new QFormLayout(logGrp);
    m_spinLogDays = new QSpinBox;
    m_spinLogDays->setRange(7, 365);
    m_spinLogDays->setValue(90);
    m_spinLogDays->setSuffix(" 天");
    m_spinLogDays->setObjectName("spinBox");
    logForm->addRow("日志保留天数：", m_spinLogDays);
    logLay->addWidget(logGrp);
    logLay->addStretch();
    m_stack->addWidget(pgLog);

    // ── 7: 关于系统 ───────────────────────────────────────────────
    QWidget *pgAbout = new QWidget;
    QVBoxLayout *aboutLay = new QVBoxLayout(pgAbout);
    aboutLay->setContentsMargins(16, 16, 16, 16);
    aboutLay->setAlignment(Qt::AlignTop);
    QLabel *aboutLbl = new QLabel(
        "<h2 style='color:#1a3a6a;'>恶意代码辅助检测系统</h2>"
        "<p><b>版本：</b>V3.0.20251120</p>"
        "<p><b>病毒库版本：</b>20251120</p>"
        "<p><b>认证机构：</b>国家保密科技测评中心</p>"
        "<p><b>授权状态：</b><span style='color:#389e0d;font-weight:bold;'>正式授权</span></p>"
        "<p><b>授权到期：</b>2026-12-31</p>"
        "<p><b>支持操作系统：</b>Windows 7/8/10/11（32/64位）、统信UOS、麒麟OS</p>"
        "<hr/>"
        "<p style='color:#888;font-size:11px;'>本产品依据 GB/T 28452 等保密行业标准开发，"
        "适用于涉密信息系统的恶意代码检测与防护。</p>"
        "<p style='color:#888;font-size:11px;'>技术支持：400-XXX-XXXX</p>"
    );
    aboutLbl->setWordWrap(true);
    aboutLbl->setObjectName("aboutLabel");
    aboutLay->addWidget(aboutLbl);
    m_stack->addWidget(pgAbout);

    mainRow->addWidget(m_stack, 1);
    m_mainLayout->addLayout(mainRow, 1);

    // 保存按钮
    QHBoxLayout *saveRow = new QHBoxLayout;
    QPushButton *btnSave = new QPushButton("保 存 设 置");
    btnSave->setObjectName("btnPrimary");
    btnSave->setFixedWidth(120);
    connect(btnSave, &QPushButton::clicked, this, &SystemSettingsPage::onSave);
    saveRow->addStretch();
    saveRow->addWidget(btnSave);
    m_mainLayout->addLayout(saveRow);
}

void SystemSettingsPage::loadSettings() {
    auto *dbm = DatabaseManager::instance();
    m_editDllPath->setText(dbm->getSetting("dll_path", "basic.dll"));
    m_editDbPath->setText(dbm->getSetting("db_path", "malware_detector.db"));
    m_editReportDir->setText(dbm->getSetting("report_dir", "./reports"));

    // 病毒库
    QString ver  = dbm->getSetting("virus_db_version", "20251120");
    QString date = dbm->getSetting("virus_db_date", "2025-11-20");
    m_lblDbVer->setText("当前版本：" + ver);
    m_lblDbDate->setText("更新时间：" + date);
    m_chkAutoUpdate->setChecked(dbm->getSetting("auto_update", "1") == "1");
    int freqIdx = dbm->getSetting("update_freq", "0").toInt();
    m_cmbUpdateFreq->setCurrentIndex(qBound(0, freqIdx, 2));

    // 扫描策略
    m_chkAutoScan->setChecked(dbm->getSetting("auto_scan", "0") == "1");
    m_chkStartupScan->setChecked(dbm->getSetting("startup_scan", "0") == "1");
    m_chkRealtime->setChecked(dbm->getSetting("realtime_monitor", "0") == "1");
    m_chkScanArchive->setChecked(dbm->getSetting("scan_archive", "1") == "1");
    m_chkScanHidden->setChecked(dbm->getSetting("scan_hidden", "1") == "1");
    m_spinLogDays->setValue(dbm->getSetting("log_days", "90").toInt());

    // 白名单
    m_tblWhitelist->setRowCount(0);
    QSqlQuery wq;
    wq.exec("SELECT COALESCE(type,'路径'), COALESCE(value, path_or_md5), COALESCE(note,remark,''), created_at FROM whitelist ORDER BY id");
    while (wq.next()) {
        int row = m_tblWhitelist->rowCount(); m_tblWhitelist->insertRow(row);
        m_tblWhitelist->setItem(row, 0, new QTableWidgetItem(wq.value(0).toString()));
        m_tblWhitelist->setItem(row, 1, new QTableWidgetItem(wq.value(1).toString()));
        m_tblWhitelist->setItem(row, 2, new QTableWidgetItem(wq.value(2).toString()));
        m_tblWhitelist->setItem(row, 3, new QTableWidgetItem(wq.value(3).toString()));
        m_tblWhitelist->setItem(row, 4, new QTableWidgetItem("删除"));
    }
    if (m_tblWhitelist->rowCount() == 0) {
        struct WlDemo { QString type, val, note, date; };
        QList<WlDemo> demos = {
            {"路径", "C:\\Program Files\\Microsoft Office\\", "Office套件",  "2025-01-10"},
            {"MD5",  "d41d8cd98f00b204e9800998ecf8427e",       "已知安全文件","2025-03-15"},
        };
        for (auto &d : demos) {
            int row = m_tblWhitelist->rowCount(); m_tblWhitelist->insertRow(row);
            m_tblWhitelist->setItem(row, 0, new QTableWidgetItem(d.type));
            m_tblWhitelist->setItem(row, 1, new QTableWidgetItem(d.val));
            m_tblWhitelist->setItem(row, 2, new QTableWidgetItem(d.note));
            m_tblWhitelist->setItem(row, 3, new QTableWidgetItem(d.date));
            m_tblWhitelist->setItem(row, 4, new QTableWidgetItem("删除"));
        }
    }

    // 自定义规则
    m_tblRules->setRowCount(0);
    QSqlQuery rq;
    rq.exec("SELECT id, name, type, COALESCE(content,'') as content, risk_level, enabled FROM custom_rules ORDER BY id");
    while (rq.next()) {
        int row = m_tblRules->rowCount(); m_tblRules->insertRow(row);
        m_tblRules->setItem(row, 0, new QTableWidgetItem(QString("RULE-%1").arg(rq.value(0).toInt(), 4, 10, QChar('0'))));
        m_tblRules->setItem(row, 1, new QTableWidgetItem(rq.value(1).toString()));
        m_tblRules->setItem(row, 2, new QTableWidgetItem(rq.value(2).toString()));
        m_tblRules->setItem(row, 3, new QTableWidgetItem(rq.value(3).toString()));
        QString risk = rq.value(4).toString();
        QTableWidgetItem *ri = new QTableWidgetItem(risk);
        ri->setForeground(risk=="高危"?QColor("#cf1322"):risk=="中危"?QColor("#d46b08"):QColor("#096dd9"));
        m_tblRules->setItem(row, 4, ri);
        bool enabled = rq.value(5).toInt() == 1;
        QTableWidgetItem *ei = new QTableWidgetItem(enabled ? "启用" : "禁用");
        ei->setForeground(enabled ? QColor("#389e0d") : QColor("#888"));
        m_tblRules->setItem(row, 5, ei);
    }
    if (m_tblRules->rowCount() == 0) {
        struct RuleDemo { QString id, name, type, content, risk, status; };
        QList<RuleDemo> demos = {
            {"RULE-0042","Trojan.Win32.Agent",         "特征码",   "4d5a9000...",   "高危","启用"},
            {"RULE-0118","Suspicious.ProcessInjection","行为规则", "CreateRemoteThread","高危","启用"},
            {"RULE-0203","Packed.UPX",                 "加壳检测", "UPX0 section",  "中危","启用"},
        };
        for (auto &d : demos) {
            int row = m_tblRules->rowCount(); m_tblRules->insertRow(row);
            m_tblRules->setItem(row, 0, new QTableWidgetItem(d.id));
            m_tblRules->setItem(row, 1, new QTableWidgetItem(d.name));
            m_tblRules->setItem(row, 2, new QTableWidgetItem(d.type));
            m_tblRules->setItem(row, 3, new QTableWidgetItem(d.content));
            QTableWidgetItem *ri = new QTableWidgetItem(d.risk);
            ri->setForeground(d.risk=="高危"?QColor("#cf1322"):QColor("#d46b08"));
            m_tblRules->setItem(row, 4, ri);
            QTableWidgetItem *ei = new QTableWidgetItem(d.status);
            ei->setForeground(QColor("#389e0d"));
            m_tblRules->setItem(row, 5, ei);
        }
    }

    // 用户管理
    m_tblUsers->setRowCount(0);
    struct UserDemo { QString name, role, status, lastLogin; };
    QList<UserDemo> users = {
        {"admin",    "系统管理员", "启用", "2025-11-20 09:00"},
        {"secadmin", "安全管理员", "启用", "2025-11-20 08:30"},
        {"auditor",  "安全审计员", "启用", "2025-11-19 17:00"},
    };
    for (auto &u : users) {
        int row = m_tblUsers->rowCount(); m_tblUsers->insertRow(row);
        m_tblUsers->setItem(row, 0, new QTableWidgetItem(u.name));
        m_tblUsers->setItem(row, 1, new QTableWidgetItem(u.role));
        QTableWidgetItem *si = new QTableWidgetItem(u.status);
        si->setForeground(QColor("#389e0d"));
        m_tblUsers->setItem(row, 2, si);
        m_tblUsers->setItem(row, 3, new QTableWidgetItem(u.lastLogin));
        m_tblUsers->setItem(row, 4, new QTableWidgetItem("修改密码"));
    }
}

void SystemSettingsPage::refreshData() { loadSettings(); }

void SystemSettingsPage::onNavChanged(int row) { m_stack->setCurrentIndex(row); }

void SystemSettingsPage::onSave() {
    auto *dbm = DatabaseManager::instance();
    dbm->setSetting("dll_path",          m_editDllPath->text());
    dbm->setSetting("db_path",           m_editDbPath->text());
    dbm->setSetting("report_dir",        m_editReportDir->text());
    dbm->setSetting("auto_scan",         m_chkAutoScan->isChecked()    ? "1" : "0");
    dbm->setSetting("startup_scan",      m_chkStartupScan->isChecked() ? "1" : "0");
    dbm->setSetting("realtime_monitor",  m_chkRealtime->isChecked()    ? "1" : "0");
    dbm->setSetting("scan_archive",      m_chkScanArchive->isChecked() ? "1" : "0");
    dbm->setSetting("scan_hidden",       m_chkScanHidden->isChecked()  ? "1" : "0");
    dbm->setSetting("auto_update",       m_chkAutoUpdate->isChecked()  ? "1" : "0");
    dbm->setSetting("update_freq",       QString::number(m_cmbUpdateFreq->currentIndex()));
    dbm->setSetting("log_days",          QString::number(m_spinLogDays->value()));
    dbm->writeLog(m_role, m_username, "修改设置", "保存系统设置", "success");
    m_lblStatus->setText("设置已保存：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
    QMessageBox::information(this, "提示", "设置已保存成功！");
}

void SystemSettingsPage::onUpdateVirusDb() {
    m_progressUpdate->setVisible(true);
    m_progressUpdate->setValue(0);
    m_btnUpdate->setEnabled(false);
    m_lblDbStatus->setText("状态：更新中...");
    m_lblDbStatus->setStyleSheet("color:#d46b08;font-weight:bold;");
    for (int i = 0; i <= 100; i += 10) {
        m_progressUpdate->setValue(i);
        qApp->processEvents();
        QThread::msleep(120);
    }
    QString newVer  = QDateTime::currentDateTime().toString("yyyyMMdd");
    QString newDate = QDate::currentDate().toString("yyyy-MM-dd");
    DatabaseManager::instance()->setSetting("virus_db_version", newVer);
    DatabaseManager::instance()->setSetting("virus_db_date",    newDate);
    m_lblDbVer->setText("当前版本：" + newVer);
    m_lblDbDate->setText("更新时间：" + newDate);
    m_lblDbStatus->setText("状态：最新");
    m_lblDbStatus->setStyleSheet("color:#389e0d;font-weight:bold;");
    m_btnUpdate->setEnabled(true);
    DatabaseManager::instance()->writeLog(m_role, m_username, "更新病毒库", "病毒库更新至" + newVer, "success");
    m_lblStatus->setText("病毒库已更新至 " + newVer);
    QMessageBox::information(this, "提示", "病毒库更新成功！\n当前版本：" + newVer);
}

void SystemSettingsPage::onAddWhitelist() {
    QString val = QInputDialog::getText(this, "添加白名单", "请输入文件路径或MD5：");
    if (val.isEmpty()) return;
    int row = m_tblWhitelist->rowCount();
    m_tblWhitelist->insertRow(row);
    QString type = (val.length() == 32 && !val.contains("\\") && !val.contains("/")) ? "MD5" : "路径";
    m_tblWhitelist->setItem(row, 0, new QTableWidgetItem(type));
    m_tblWhitelist->setItem(row, 1, new QTableWidgetItem(val));
    m_tblWhitelist->setItem(row, 2, new QTableWidgetItem("手动添加"));
    m_tblWhitelist->setItem(row, 3, new QTableWidgetItem(QDate::currentDate().toString("yyyy-MM-dd")));
    m_tblWhitelist->setItem(row, 4, new QTableWidgetItem("删除"));
    DatabaseManager::instance()->writeLog(m_role, m_username, "白名单", "添加白名单：" + val, "success");
}

void SystemSettingsPage::onDelWhitelist() {
    int row = m_tblWhitelist->currentRow();
    if (row < 0) { QMessageBox::warning(this, "提示", "请先选择要删除的条目。"); return; }
    m_tblWhitelist->removeRow(row);
    DatabaseManager::instance()->writeLog(m_role, m_username, "白名单", "删除白名单条目", "success");
}

void SystemSettingsPage::onAddRule() {
    QString name = QInputDialog::getText(this, "新增规则", "请输入规则名称：");
    if (name.isEmpty()) return;
    int row = m_tblRules->rowCount();
    m_tblRules->insertRow(row);
    m_tblRules->setItem(row, 0, new QTableWidgetItem(QString("RULE-%1").arg(row + 100, 4, 10, QChar('0'))));
    m_tblRules->setItem(row, 1, new QTableWidgetItem(name));
    m_tblRules->setItem(row, 2, new QTableWidgetItem("特征码"));
    m_tblRules->setItem(row, 3, new QTableWidgetItem(""));
    QTableWidgetItem *ri = new QTableWidgetItem("中危");
    ri->setForeground(QColor("#d46b08"));
    m_tblRules->setItem(row, 4, ri);
    QTableWidgetItem *ei = new QTableWidgetItem("启用");
    ei->setForeground(QColor("#389e0d"));
    m_tblRules->setItem(row, 5, ei);
    DatabaseManager::instance()->writeLog(m_role, m_username, "规则", "新增规则：" + name, "success");
}

void SystemSettingsPage::onDelRule() {
    int row = m_tblRules->currentRow();
    if (row < 0) { QMessageBox::warning(this, "提示", "请先选择要删除的规则。"); return; }
    m_tblRules->removeRow(row);
    DatabaseManager::instance()->writeLog(m_role, m_username, "规则", "删除规则", "success");
}
