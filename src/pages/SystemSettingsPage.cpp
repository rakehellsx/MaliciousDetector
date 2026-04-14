#include "pages/SystemSettingsPage.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QLabel>
#include <QFileDialog>
#include <QMessageBox>
#include <QPushButton>

SystemSettingsPage::SystemSettingsPage(QWidget *parent) : BasePage("系统设置", parent) { setupUi(); loadSettings(); }

void SystemSettingsPage::setupUi()
{
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
    m_navList->addItem("  日志设置");
    m_navList->addItem("  关于系统");
    m_navList->setCurrentRow(0);
    connect(m_navList, &QListWidget::currentRowChanged, this, &SystemSettingsPage::onNavChanged);
    mainRow->addWidget(m_navList);

    // 右侧内容
    m_stack = new QStackedWidget;
    m_stack->setObjectName("settingsStack");

    // ── 0: 基础配置 ──────────────────────────────────────────
    QWidget *pgBase = new QWidget;
    QVBoxLayout *baseLay = new QVBoxLayout(pgBase);
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

    // ── 1: 病毒库管理 ─────────────────────────────────────────
    QWidget *pgVirus = new QWidget;
    QVBoxLayout *virusLay = new QVBoxLayout(pgVirus);
    QGroupBox *virusGrp = new QGroupBox("病毒库信息");
    virusGrp->setObjectName("settingsGroup");
    QFormLayout *virusForm = new QFormLayout(virusGrp);
    m_lblDbVer  = new QLabel("--");
    m_lblDbDate = new QLabel("--");
    virusForm->addRow("当前版本：", m_lblDbVer);
    virusForm->addRow("更新日期：", m_lblDbDate);
    QLabel *srcLbl = new QLabel("更新源：仅支持内网离线更新源");
    srcLbl->setObjectName("infoLabel");
    virusForm->addRow("更新来源：", srcLbl);
    m_btnUpdate = new QPushButton("立即更新病毒库");
    m_btnUpdate->setObjectName("btnPrimary");
    m_btnUpdate->setFixedWidth(160);
    connect(m_btnUpdate, &QPushButton::clicked, this, &SystemSettingsPage::onUpdateVirusDb);
    virusForm->addRow("", m_btnUpdate);
    virusLay->addWidget(virusGrp);
    virusLay->addStretch();
    m_stack->addWidget(pgVirus);

    // ── 2: 扫描策略 ───────────────────────────────────────────
    QWidget *pgScan = new QWidget;
    QVBoxLayout *scanLay = new QVBoxLayout(pgScan);
    QGroupBox *scanGrp = new QGroupBox("扫描策略");
    scanGrp->setObjectName("settingsGroup");
    QVBoxLayout *scanGrpLay = new QVBoxLayout(scanGrp);
    m_chkAutoScan    = new QCheckBox("启用定时自动扫描");
    m_chkStartupScan = new QCheckBox("系统启动时自动扫描");
    m_chkRealtime    = new QCheckBox("启用实时监控（需要驱动支持）");
    m_chkAutoScan->setObjectName("settingsCheck");
    m_chkStartupScan->setObjectName("settingsCheck");
    m_chkRealtime->setObjectName("settingsCheck");
    scanGrpLay->addWidget(m_chkAutoScan);
    scanGrpLay->addWidget(m_chkStartupScan);
    scanGrpLay->addWidget(m_chkRealtime);
    scanLay->addWidget(scanGrp);
    scanLay->addStretch();
    m_stack->addWidget(pgScan);

    // ── 3: 白名单管理 ─────────────────────────────────────────
    QWidget *pgWhite = new QWidget;
    QVBoxLayout *whiteLay = new QVBoxLayout(pgWhite);
    QHBoxLayout *whiteBtn = new QHBoxLayout;
    m_btnAddWhite = new QPushButton("添加");
    m_btnAddWhite->setObjectName("btnPrimary");
    m_btnDelWhite = new QPushButton("删除");
    m_btnDelWhite->setObjectName("btnWarning");
    whiteBtn->addWidget(m_btnAddWhite);
    whiteBtn->addWidget(m_btnDelWhite);
    whiteBtn->addStretch();
    whiteLay->addLayout(whiteBtn);
    m_tblWhitelist = new QTableWidget(0, 3);
    m_tblWhitelist->setHorizontalHeaderLabels({"文件路径/MD5","类型","备注"});
    styleTable(m_tblWhitelist);
    m_tblWhitelist->setColumnWidth(0, 300);
    m_tblWhitelist->setColumnWidth(1, 80);
    whiteLay->addWidget(m_tblWhitelist, 1);
    m_stack->addWidget(pgWhite);

    // ── 4: 自定义规则 ─────────────────────────────────────────
    QWidget *pgRules = new QWidget;
    QVBoxLayout *rulesLay = new QVBoxLayout(pgRules);
    QHBoxLayout *rulesBtn = new QHBoxLayout;
    m_btnAddRule = new QPushButton("添加规则");
    m_btnAddRule->setObjectName("btnPrimary");
    m_btnDelRule = new QPushButton("删除规则");
    m_btnDelRule->setObjectName("btnWarning");
    rulesBtn->addWidget(m_btnAddRule);
    rulesBtn->addWidget(m_btnDelRule);
    rulesBtn->addStretch();
    rulesLay->addLayout(rulesBtn);
    m_tblRules = new QTableWidget(0, 4);
    m_tblRules->setHorizontalHeaderLabels({"规则名称","规则类型","规则内容","风险等级"});
    styleTable(m_tblRules);
    m_tblRules->setColumnWidth(0, 160);
    m_tblRules->setColumnWidth(1, 100);
    rulesLay->addWidget(m_tblRules, 1);
    m_stack->addWidget(pgRules);

    // ── 5: 日志设置 ───────────────────────────────────────────
    QWidget *pgLog = new QWidget;
    QVBoxLayout *logLay = new QVBoxLayout(pgLog);
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

    // ── 6: 关于系统 ───────────────────────────────────────────
    QWidget *pgAbout = new QWidget;
    QVBoxLayout *aboutLay = new QVBoxLayout(pgAbout);
    aboutLay->setAlignment(Qt::AlignTop);
    QLabel *aboutLbl = new QLabel(
        "<h2 style='color:#4fc3f7;'>恶意代码辅助检测系统</h2>"
        "<p style='color:#90caf9;'>版本：V3.0.20251120</p>"
        "<p style='color:#90caf9;'>病毒库版本：20251120</p>"
        "<p style='color:#90caf9;'>国家保密科技测评中心 认证产品</p>"
        "<hr style='border:1px solid #2a4a6e;'/>"
        "<p style='color:#546e7a;'>本产品依据 GB/T 28452 等保密行业标准开发，<br/>"
        "适用于涉密信息系统的恶意代码检测与防护。</p>"
        "<p style='color:#546e7a;'>技术支持：请联系系统管理员</p>"
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

void SystemSettingsPage::loadSettings()
{
    m_editDllPath->setText(DatabaseManager::instance()->getSetting("dll_path","basic.dll"));
    m_editDbPath->setText(DatabaseManager::instance()->getSetting("db_path","malware_detector.db"));
    m_editReportDir->setText(DatabaseManager::instance()->getSetting("report_dir","./reports"));
    m_lblDbVer->setText(DatabaseManager::instance()->getSetting("virus_db_version","20251120"));
    m_lblDbDate->setText(DatabaseManager::instance()->getSetting("virus_db_date","2025-11-20"));
    m_chkAutoScan->setChecked(DatabaseManager::instance()->getSetting("auto_scan","0")=="1");
    m_chkStartupScan->setChecked(DatabaseManager::instance()->getSetting("startup_scan","0")=="1");
    m_chkRealtime->setChecked(DatabaseManager::instance()->getSetting("realtime_monitor","0")=="1");
    m_spinLogDays->setValue(DatabaseManager::instance()->getSetting("log_days","90").toInt());

    // 白名单
    m_tblWhitelist->setRowCount(0);
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.exec("SELECT path_or_md5,type,remark FROM whitelist ORDER BY id");
        while (q.next()) {
            int row = m_tblWhitelist->rowCount(); m_tblWhitelist->insertRow(row);
            m_tblWhitelist->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));
            m_tblWhitelist->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
            m_tblWhitelist->setItem(row,2,new QTableWidgetItem(q.value(2).toString()));
        }
        // 自定义规则
        m_tblRules->setRowCount(0);
        q.exec("SELECT name,type,content,risk_level FROM custom_rules ORDER BY id");
        while (q.next()) {
            int row = m_tblRules->rowCount(); m_tblRules->insertRow(row);
            m_tblRules->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));
            m_tblRules->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
            m_tblRules->setItem(row,2,new QTableWidgetItem(q.value(2).toString()));
            m_tblRules->setItem(row,3,new QTableWidgetItem(q.value(3).toString()));
        }
    }
}

void SystemSettingsPage::refreshData() { loadSettings(); }

void SystemSettingsPage::onNavChanged(int row) { m_stack->setCurrentIndex(row); }

void SystemSettingsPage::onSave()
{
    DatabaseManager::instance()->setSetting("dll_path",    m_editDllPath->text());
    DatabaseManager::instance()->setSetting("db_path",     m_editDbPath->text());
    DatabaseManager::instance()->setSetting("report_dir",  m_editReportDir->text());
    DatabaseManager::instance()->setSetting("auto_scan",   m_chkAutoScan->isChecked()?"1":"0");
    DatabaseManager::instance()->setSetting("startup_scan",m_chkStartupScan->isChecked()?"1":"0");
    DatabaseManager::instance()->setSetting("realtime_monitor",m_chkRealtime->isChecked()?"1":"0");
    DatabaseManager::instance()->setSetting("log_days",    QString::number(m_spinLogDays->value()));
    DatabaseManager::instance()->writeLog(m_role, m_username, "修改设置", "保存系统设置", "success");
    m_lblStatus->setText("设置已保存");
    QMessageBox::information(this, "提示", "设置已保存成功！");
}

void SystemSettingsPage::onUpdateVirusDb()
{
    // 实际项目：从内网更新源下载病毒库
    QString newVer = QDateTime::currentDateTime().toString("yyyyMMdd");
    DatabaseManager::instance()->setSetting("virus_db_version", newVer);
    DatabaseManager::instance()->setSetting("virus_db_date", QDate::currentDate().toString("yyyy-MM-dd"));
    m_lblDbVer->setText(newVer);
    m_lblDbDate->setText(QDate::currentDate().toString("yyyy-MM-dd"));
    DatabaseManager::instance()->writeLog(m_role, m_username, "更新病毒库", "病毒库更新至"+newVer, "success");
    m_lblStatus->setText("病毒库已更新至 " + newVer);
    QMessageBox::information(this, "提示", "病毒库更新成功！\n当前版本：" + newVer);
}
