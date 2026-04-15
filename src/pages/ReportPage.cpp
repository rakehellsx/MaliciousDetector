#include "pages/ReportPage.h"
#include "ui_ReportPage.h"

#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QFormLayout>
#include <QSplitter>
#include <QScrollArea>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QDateTime>
#include <QFile>
#include <QTextStream>
#include <QFont>
#include <QFrame>
#include <QGroupBox>
#include <QPrinter>
#include <QTextDocument>
#include <QDir>

// ─────────────────────────────────────────────────────────────────────────────
// 辅助函数
// ─────────────────────────────────────────────────────────────────────────────
static QLabel *makeCardLabel(const QString &bg, const QString &fg) {
    QLabel *lbl = new QLabel("0");
    lbl->setAlignment(Qt::AlignCenter);
    lbl->setFixedSize(130, 80);
    lbl->setStyleSheet(QString(
        "QLabel{background:%1;color:%2;border-radius:6px;"
        "font-size:28px;font-weight:700;}").arg(bg, fg));
    return lbl;
}

static QTableWidget *makeTable(const QStringList &headers) {
    QTableWidget *t = new QTableWidget(0, headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    t->horizontalHeader()->setStretchLastSection(true);
    t->verticalHeader()->setVisible(false);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setAlternatingRowColors(true);
    t->setStyleSheet(
        "QTableWidget{border:1px solid #d0d7e3;font-size:12px;}"
        "QHeaderView::section{background:#e8ecf4;padding:5px 8px;"
        "font-weight:600;border:1px solid #d0d7e3;}"
        "QTableWidget::item{padding:5px 8px;}"
        "QTableWidget::item:alternate{background:#fafbfd;}");
    return t;
}

static QTableWidgetItem *riskItem(const QString &risk) {
    struct { const char *key; const char *zh; const char *color; } map[] = {
        {"high",   "高危", "#f5222d"},
        {"medium", "中危", "#fa8c16"},
        {"low",    "低危", "#1890ff"},
        {"clean",  "安全", "#52c41a"},
        {nullptr, nullptr, nullptr}
    };
    QString text = risk, color = "#555";
    for (int i = 0; map[i].key; i++) {
        if (risk == map[i].key) { text = map[i].zh; color = map[i].color; break; }
    }
    QTableWidgetItem *item = new QTableWidgetItem(text);
    QFont f = item->font(); f.setBold(true); item->setFont(f);
    item->setForeground(QColor(color));
    item->setTextAlignment(Qt::AlignCenter);
    return item;
}

static void highlightRow(QTableWidget *t, int row, const QString &risk) {
    QColor bg;
    if (risk == "high")   bg = QColor("#fff1f0");
    else if (risk == "medium") bg = QColor("#fffbe6");
    if (!bg.isValid()) return;
    for (int c = 0; c < t->columnCount(); c++)
        if (t->item(row, c)) t->item(row, c)->setBackground(bg);
}

static QString escHtml(const QString &s) {
    QString r = s;
    r.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;");
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
// 构造 / 析构
// ─────────────────────────────────────────────────────────────────────────────
ReportPage::ReportPage(QWidget *parent)
    : BasePage("检测报告", parent)
    , m_timer(new QTimer(this))
{
    connect(m_timer, &QTimer::timeout, this, &ReportPage::onTimerFired);
    ui = new Ui::ReportPage();
    ui->setupUi(this);
    m_lblReportId = ui->m_lblReportId;
    m_lblReportTime = ui->m_lblReportTime;
    m_lblHostname = ui->m_lblHostname;
    m_lblOs = ui->m_lblOs;
    m_lblIp = ui->m_lblIp;
    m_lblCollectTime = ui->m_lblCollectTime;
    m_cardHighCount = ui->m_cardHighCount;
    m_cardMediumCount = ui->m_cardMediumCount;
    m_cardLowCount = ui->m_cardLowCount;
    m_cardCleanCount = ui->m_cardCleanCount;
    m_tblModuleStat = ui->m_tblModuleStat;
    m_edtThreatKw = ui->m_edtThreatKw;
    m_cmbThreatRisk = ui->m_cmbThreatRisk;
    m_cmbThreatCat = ui->m_cmbThreatCat;
    m_lblThreatCount = ui->m_lblThreatCount;
    m_tblThreats = ui->m_tblThreats;
    m_tblSysInfo = ui->m_tblSysInfo;
    m_tblNetInfo = ui->m_tblNetInfo;
    m_tblDiskInfo = ui->m_tblDiskInfo;
    m_tblProcRisk = ui->m_tblProcRisk;
    m_tblPortRisk = ui->m_tblPortRisk;
    m_txtPreview = ui->m_txtPreview;
    m_chkTimerEnable = ui->m_chkTimerEnable;
    m_cmbTimerMode = ui->m_cmbTimerMode;
    m_spnTimerHour = ui->m_spnTimerHour;
    m_spnTimerMinute = ui->m_spnTimerMinute;
    m_lblNextTime = ui->m_lblNextTime;
    m_lblTimerStatus = ui->m_lblTimerStatus;
    m_tblHistory = ui->m_tblHistory;
    m_btnExportHistHtml = ui->m_btnExportHistHtml;
    m_btnExportHistDoc = ui->m_btnExportHistDoc;
    m_btnExportHistPdf = ui->m_btnExportHistPdf;
    m_btnDeleteHist = ui->m_btnDeleteHist;
    m_lblHistDetail = ui->m_lblHistDetail;
    m_btnGenerate = ui->m_btnGenerate;
    m_btnExportDoc = ui->m_btnExportDoc;
    m_btnExportPdf = ui->m_btnExportPdf;
    m_btnExportHtml = ui->m_btnExportHtml;
    m_lblStatus = ui->m_lblStatus;
    m_tabMain = ui->m_tabMain;
    refreshData();
}

ReportPage::~ReportPage() {}

// ─────────────────────────────────────────────────────────────────────────────
// UI 构建
// ─────────────────────────────────────────────────────────────────────────────

// ── 概览 Tab ─────────────────────────────────────────────────────────────────
void ReportPage::setupOverviewTab(QWidget *tab)
{
    QVBoxLayout *lay = new QVBoxLayout(tab);
    lay->setContentsMargins(12, 12, 12, 12);
    lay->setSpacing(12);

    QString gbStyle = "QGroupBox{font-weight:600;font-size:12px;border:1px solid #d0d7e3;"
                      "border-radius:4px;margin-top:8px;padding-top:8px;}"
                      "QGroupBox::title{subcontrol-origin:margin;left:8px;padding:0 4px;}";

    // 报告基本信息
    QGroupBox *gbInfo = new QGroupBox("报告信息");
    gbInfo->setStyleSheet(gbStyle);
    QGridLayout *infoGrid = new QGridLayout(gbInfo);
    infoGrid->setSpacing(8);

    auto addInfoRow = [&](int idx, const QString &label, QLabel *&out) {
        QLabel *lbl = new QLabel(label);
        lbl->setStyleSheet("font-size:12px;color:#595959;font-weight:600;");
        out = new QLabel("--");
        out->setStyleSheet("font-size:12px;color:#262626;");
        infoGrid->addWidget(lbl, idx/2, (idx%2)*2,     Qt::AlignRight);
        infoGrid->addWidget(out, idx/2, (idx%2)*2 + 1, Qt::AlignLeft);
    };
    addInfoRow(0, "报告编号：",   m_lblReportId);
    addInfoRow(1, "生成时间：",   m_lblReportTime);
    addInfoRow(2, "主机名称：",   m_lblHostname);
    addInfoRow(3, "操作系统：",   m_lblOs);
    addInfoRow(4, "IP 地址：",    m_lblIp);
    addInfoRow(5, "数据采集时间：", m_lblCollectTime);
    lay->addWidget(gbInfo);

    // 风险统计卡片
    QGroupBox *gbRisk = new QGroupBox("风险统计");
    gbRisk->setStyleSheet(gbStyle);
    QHBoxLayout *cardRow = new QHBoxLayout(gbRisk);
    cardRow->setSpacing(16);
    cardRow->setContentsMargins(12, 12, 12, 12);

    struct { const char *title; const char *bg; const char *fg; QLabel **ptr; } cards[] = {
        {"高危威胁", "#fff1f0", "#f5222d", &m_cardHighCount},
        {"中危威胁", "#fffbe6", "#d46b08", &m_cardMediumCount},
        {"低危威胁", "#e6f7ff", "#0050b3", &m_cardLowCount},
        {"安全项目", "#f6ffed", "#389e0d", &m_cardCleanCount},
    };
    for (auto &c : cards) {
        QVBoxLayout *vl = new QVBoxLayout;
        vl->setSpacing(2);
        vl->setContentsMargins(0,0,0,0);
        *c.ptr = makeCardLabel(c.bg, c.fg);
        QLabel *titleLbl = new QLabel(c.title);
        titleLbl->setAlignment(Qt::AlignCenter);
        titleLbl->setStyleSheet(QString("QLabel{background:%1;color:%2;"
            "font-size:11px;font-weight:600;border-radius:0 0 4px 4px;}").arg(c.bg, c.fg));
        vl->addWidget(*c.ptr);
        vl->addWidget(titleLbl);
        cardRow->addLayout(vl);
    }
    cardRow->addStretch();
    lay->addWidget(gbRisk);

    // 各模块统计表
    QGroupBox *gbMod = new QGroupBox("各模块风险分布");
    gbMod->setStyleSheet(gbStyle);
    QVBoxLayout *modLay = new QVBoxLayout(gbMod);
    m_tblModuleStat = makeTable({"检测模块","高危","中危","低危","安全/正常","合计","风险状态"});
    m_tblModuleStat->setMaximumHeight(260);
    modLay->addWidget(m_tblModuleStat);
    lay->addWidget(gbMod, 1);
}

// ── 威胁详情 Tab ─────────────────────────────────────────────────────────────
void ReportPage::setupThreatTab(QWidget *tab)
{
    QVBoxLayout *lay = new QVBoxLayout(tab);
    lay->setContentsMargins(12, 12, 12, 12);
    lay->setSpacing(8);

    QHBoxLayout *qrow = new QHBoxLayout;
    qrow->setSpacing(6);

    m_edtThreatKw = new QLineEdit;
    m_edtThreatKw->setPlaceholderText("威胁名称 / 文件路径 / 详情");
    m_edtThreatKw->setClearButtonEnabled(true);
    m_edtThreatKw->setFixedWidth(220);
    connect(m_edtThreatKw, &QLineEdit::returnPressed, this, &ReportPage::onQueryThreats);

    m_cmbThreatRisk = new QComboBox;
    m_cmbThreatRisk->addItems({"全部风险","高危","中危","低危","安全"});
    connect(m_cmbThreatRisk, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ReportPage::onQueryThreats);

    m_cmbThreatCat = new QComboBox;
    m_cmbThreatCat->addItems({"全部类别","静态扫描","动态行为","文件关联",
                               "端口风险","进程风险","驱动风险","自启动风险","证书异常"});
    connect(m_cmbThreatCat, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ReportPage::onQueryThreats);

    QPushButton *btnQ = new QPushButton("查询");
    btnQ->setFixedWidth(70);
    btnQ->setStyleSheet("QPushButton{background:#1a3a6a;color:#fff;border:none;"
                        "border-radius:3px;padding:5px 10px;font-size:12px;font-weight:600;}");
    connect(btnQ, &QPushButton::clicked, this, &ReportPage::onQueryThreats);

    QPushButton *btnR = new QPushButton("刷新");
    btnR->setFixedWidth(70);
    btnR->setStyleSheet("QPushButton{background:#595959;color:#fff;border:none;"
                        "border-radius:3px;padding:5px 10px;font-size:12px;}");
    connect(btnR, &QPushButton::clicked, this, &ReportPage::refreshData);

    m_lblThreatCount = new QLabel;
    m_lblThreatCount->setStyleSheet("font-size:11px;color:#8c8c8c;padding:0 8px;");

    qrow->addWidget(new QLabel("关键字："));
    qrow->addWidget(m_edtThreatKw);
    qrow->addSpacing(8);
    qrow->addWidget(new QLabel("风险："));
    qrow->addWidget(m_cmbThreatRisk);
    qrow->addSpacing(8);
    qrow->addWidget(new QLabel("类别："));
    qrow->addWidget(m_cmbThreatCat);
    qrow->addWidget(btnQ);
    qrow->addWidget(btnR);
    qrow->addWidget(m_lblThreatCount);
    qrow->addStretch();
    lay->addLayout(qrow);

    m_tblThreats = makeTable({"威胁名称","风险等级","威胁类别","文件路径","详细信息","发现时间","处置状态"});
    m_tblThreats->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_tblThreats->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    lay->addWidget(m_tblThreats, 1);
}

// ── 主机信息 Tab ─────────────────────────────────────────────────────────────
void ReportPage::setupHostTab(QWidget *tab)
{
    QScrollArea *scroll = new QScrollArea(tab);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    QVBoxLayout *outerLay = new QVBoxLayout(tab);
    outerLay->setContentsMargins(0,0,0,0);
    outerLay->addWidget(scroll);

    QWidget *inner = new QWidget;
    QVBoxLayout *lay = new QVBoxLayout(inner);
    lay->setContentsMargins(12,12,12,12);
    lay->setSpacing(12);
    scroll->setWidget(inner);

    QString gbStyle = "QGroupBox{font-weight:600;font-size:12px;border:1px solid #d0d7e3;"
                      "border-radius:4px;margin-top:8px;padding-top:8px;}"
                      "QGroupBox::title{subcontrol-origin:margin;left:8px;padding:0 4px;}";

    auto addSection = [&](const QString &title, QTableWidget *&tbl,
                          const QStringList &headers, int maxH) {
        QGroupBox *gb = new QGroupBox(title);
        gb->setStyleSheet(gbStyle);
        QVBoxLayout *vl = new QVBoxLayout(gb);
        tbl = makeTable(headers);
        tbl->setMaximumHeight(maxH);
        vl->addWidget(tbl);
        lay->addWidget(gb);
    };

    addSection("系统基本信息", m_tblSysInfo, {"项目","值"}, 220);
    addSection("网络接口信息", m_tblNetInfo,
               {"网卡名","IP 地址","子网掩码","网关","MAC 地址","状态"}, 160);
    addSection("磁盘信息", m_tblDiskInfo,
               {"盘符","类型","文件系统","总容量(GB)","可用(GB)","使用率"}, 160);
    addSection("高风险进程", m_tblProcRisk,
               {"PID","进程名","路径","用户","CPU%","内存(MB)","风险"}, 200);
    addSection("高风险端口", m_tblPortRisk,
               {"协议","本地IP","本地端口","远程IP","远程端口","进程","风险"}, 200);
    lay->addStretch();
}

// ── 报告预览 Tab ─────────────────────────────────────────────────────────────
void ReportPage::setupPreviewTab(QWidget *tab)
{
    QVBoxLayout *lay = new QVBoxLayout(tab);
    lay->setContentsMargins(12,12,12,12);
    m_txtPreview = new QTextEdit;
    m_txtPreview->setReadOnly(true);
    m_txtPreview->setStyleSheet(
        "QTextEdit{font-family:SimHei,Arial;font-size:13px;"
        "border:1px solid #d0d7e3;background:#fff;padding:8px;}");
    lay->addWidget(m_txtPreview);
}

// ── 定时生成 Tab ─────────────────────────────────────────────────────────────
void ReportPage::setupScheduleTab(QWidget *tab)
{
    QVBoxLayout *lay = new QVBoxLayout(tab);
    lay->setContentsMargins(20,20,20,20);
    lay->setSpacing(14);

    QString gbStyle = "QGroupBox{font-weight:600;font-size:12px;border:1px solid #d0d7e3;"
                      "border-radius:4px;margin-top:8px;padding-top:8px;}"
                      "QGroupBox::title{subcontrol-origin:margin;left:8px;padding:0 4px;}";

    QGroupBox *gb = new QGroupBox("定时生成设置");
    gb->setStyleSheet(gbStyle);
    QFormLayout *form = new QFormLayout(gb);
    form->setSpacing(10);
    form->setContentsMargins(16,12,16,12);

    m_chkTimerEnable = new QCheckBox("启用定时自动生成报告");
    m_chkTimerEnable->setStyleSheet("font-size:12px;");
    connect(m_chkTimerEnable, &QCheckBox::toggled, this, &ReportPage::onTimerToggle);
    form->addRow(m_chkTimerEnable);

    m_cmbTimerMode = new QComboBox;
    m_cmbTimerMode->addItems({"每天","每周（周一）","每周（周五）","每小时"});
    m_cmbTimerMode->setEnabled(false);
    form->addRow("生成频率：", m_cmbTimerMode);

    // 时/分 SpinBox
    QHBoxLayout *timeLay = new QHBoxLayout;
    m_spnTimerHour = new QSpinBox;
    m_spnTimerHour->setRange(0, 23);
    m_spnTimerHour->setValue(8);
    m_spnTimerHour->setSuffix(" 时");
    m_spnTimerHour->setEnabled(false);
    m_spnTimerMinute = new QSpinBox;
    m_spnTimerMinute->setRange(0, 59);
    m_spnTimerMinute->setValue(0);
    m_spnTimerMinute->setSuffix(" 分");
    m_spnTimerMinute->setEnabled(false);
    timeLay->addWidget(m_spnTimerHour);
    timeLay->addWidget(m_spnTimerMinute);
    timeLay->addStretch();
    form->addRow("生成时刻：", timeLay);

    // 保存策略按钮
    QPushButton *btnSave = new QPushButton("保存策略");
    btnSave->setStyleSheet(
        "QPushButton{background:#1a3a6a;color:#fff;border:none;border-radius:3px;"
        "padding:5px 18px;font-size:12px;font-weight:600;}"
        "QPushButton:hover{background:#0050b3;}");
    connect(btnSave, &QPushButton::clicked, this, [this](){
        QStringList modes = {"每天","每周一","每周五","每小时"};
        QString mode = modes.value(m_cmbTimerMode->currentIndex(), "每天");
        bool ok = DatabaseManager::instance()->saveReportSchedule(
            m_chkTimerEnable->isChecked(), mode,
            m_spnTimerHour->value(), m_spnTimerMinute->value(),
            m_nextFireTime.isValid()
                ? m_nextFireTime.toString("yyyy-MM-dd HH:mm:ss")
                : QString());
        m_lblTimerStatus->setText(ok ? "策略已保存到数据库" : "保存失败");
    });
    form->addRow(btnSave);

    m_lblNextTime = new QLabel("--");
    m_lblNextTime->setStyleSheet("font-size:12px;color:#1a3a6a;font-weight:600;");
    form->addRow("下次生成时间：", m_lblNextTime);

    m_lblTimerStatus = new QLabel("定时生成未启用");
    m_lblTimerStatus->setStyleSheet("font-size:11px;color:#8c8c8c;");
    form->addRow("状态：", m_lblTimerStatus);

    lay->addWidget(gb);
    lay->addStretch();

    // 启动时从 DB 恢复策略
    restoreScheduleFromDb();
}


// ─────────────────────────────────────────────────────────────────────────────
// 数据收集
// ─────────────────────────────────────────────────────────────────────────────
void ReportPage::collectData(ReportData &d)
{
    d = ReportData{};
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (!db.isOpen()) return;

    d.reportId   = "RPT-" + QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss");
    d.reportTime = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    d.analyst    = m_username.isEmpty() ? "系统" : m_username;

    // 主机信息
    auto sysVal = [&](const QString &key) -> QString {
        QSqlQuery q(db);
        q.prepare("SELECT value FROM sys_info WHERE key=? LIMIT 1");
        q.addBindValue(key);
        return (q.exec() && q.next()) ? q.value(0).toString() : "--";
    };
    d.hostname    = sysVal("hostname");
    d.os          = sysVal("os_name") + " " + sysVal("os_version");
    d.cpu         = sysVal("cpu_model");
    d.memory      = sysVal("total_memory");
    d.collectTime = sysVal("collect_time");

    {
        QSqlQuery q(db);
        q.exec("SELECT ip FROM net_info WHERE status='已连接' LIMIT 1");
        d.ip = q.next() ? q.value(0).toString() : "--";
        q.exec("SELECT mac FROM net_info LIMIT 1");
        d.mac = q.next() ? q.value(0).toString() : "--";
    }

    // ── 静态扫描 ──────────────────────────────────────────────────────────
    {
        QSqlQuery q(db);
        q.exec("SELECT risk_level,COUNT(*) FROM static_scan GROUP BY risk_level");
        int h=0,m=0,l=0,c=0;
        while(q.next()) {
            QString r=q.value(0).toString(); int n=q.value(1).toInt();
            if(r=="high") h+=n; else if(r=="medium") m+=n;
            else if(r=="low") l+=n; else c+=n;
        }
        d.moduleStat["静态扫描"] = {h,m,l,c};
        d.totalHigh+=h; d.totalMedium+=m; d.totalLow+=l; d.totalClean+=c;

        QSqlQuery qt(db);
        qt.exec("SELECT virus_name,risk_level,file_type,file_path,conclusion,scan_time "
                "FROM static_scan WHERE risk_level IN ('high','medium','low') "
                "ORDER BY CASE risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END");
        while(qt.next()) {
            ThreatItem ti;
            ti.name      = qt.value(0).toString().isEmpty() ? qt.value(2).toString() : qt.value(0).toString();
            ti.riskLevel = qt.value(1).toString();
            ti.category  = "静态扫描";
            ti.filePath  = qt.value(3).toString();
            ti.detail    = qt.value(4).toString();
            ti.scanTime  = qt.value(5).toString().left(19);
            ti.status    = "待处理";
            d.threats.append(ti);
        }
    }

    // ── 动态行为 ──────────────────────────────────────────────────────────
    {
        QSqlQuery q(db);
        q.exec("SELECT risk_level,COUNT(*) FROM dynamic_scan GROUP BY risk_level");
        int h=0,m=0,l=0;
        while(q.next()) {
            QString r=q.value(0).toString(); int n=q.value(1).toInt();
            if(r=="high") h+=n; else if(r=="medium") m+=n; else l+=n;
        }
        d.moduleStat["动态行为"] = {h,m,l,0};
        d.totalHigh+=h; d.totalMedium+=m; d.totalLow+=l;

        QSqlQuery qt(db);
        qt.exec("SELECT action_type,risk_level,behavior_type,target_path,detail,scan_time "
                "FROM dynamic_scan WHERE risk_level='high' ORDER BY id DESC LIMIT 30");
        while(qt.next()) {
            ThreatItem ti;
            ti.name      = qt.value(0).toString();
            ti.riskLevel = qt.value(1).toString();
            ti.category  = "动态行为";
            ti.filePath  = qt.value(3).toString();
            ti.detail    = qt.value(4).toString();
            ti.scanTime  = qt.value(5).toString().left(19);
            ti.status    = "待处理";
            d.threats.append(ti);
        }
    }

    // ── 文件关联 ──────────────────────────────────────────────────────────
    {
        QSqlQuery q(db);
        q.exec("SELECT risk_level,COUNT(*) FROM file_assoc_scan GROUP BY risk_level");
        int h=0,m=0,l=0;
        while(q.next()) {
            QString r=q.value(0).toString(); int n=q.value(1).toInt();
            if(r=="high") h+=n; else if(r=="medium") m+=n; else l+=n;
        }
        d.moduleStat["文件关联"] = {h,m,l,0};
        d.totalHigh+=h; d.totalMedium+=m; d.totalLow+=l;

        QSqlQuery qt(db);
        qt.exec("SELECT ext,risk_level,current_cmd,original_cmd,scan_time "
                "FROM file_assoc_scan WHERE risk_level IN ('high','medium') ORDER BY id DESC LIMIT 20");
        while(qt.next()) {
            ThreatItem ti;
            ti.name      = qt.value(0).toString() + " 关联被篡改";
            ti.riskLevel = qt.value(1).toString();
            ti.category  = "文件关联";
            ti.filePath  = qt.value(2).toString();
            ti.detail    = "原始：" + qt.value(3).toString();
            ti.scanTime  = qt.value(4).toString().left(19);
            ti.status    = "待处理";
            d.threats.append(ti);
        }
    }

    // ── 端口风险 ──────────────────────────────────────────────────────────
    {
        QSqlQuery q(db);
        q.exec("SELECT risk,COUNT(*) FROM port_info GROUP BY risk");
        int h=0,m=0,l=0,c=0;
        while(q.next()) {
            QString r=q.value(0).toString(); int n=q.value(1).toInt();
            if(r=="high") h+=n; else if(r=="medium") m+=n;
            else if(r=="low") l+=n; else c+=n;
        }
        d.moduleStat["端口检测"] = {h,m,l,c};
        d.totalHigh+=h; d.totalMedium+=m; d.totalLow+=l; d.totalClean+=c;

        QSqlQuery qt(db);
        qt.exec("SELECT process_name,risk,protocol,local_ip,local_port,remote_ip,collected_at "
                "FROM port_info WHERE risk IN ('high','medium') ORDER BY id DESC LIMIT 20");
        while(qt.next()) {
            ThreatItem ti;
            ti.name      = qt.value(0).toString() + " 高危端口";
            ti.riskLevel = qt.value(1).toString();
            ti.category  = "端口风险";
            ti.filePath  = qt.value(3).toString() + ":" + qt.value(4).toString();
            ti.detail    = qt.value(2).toString() + " → " + qt.value(5).toString();
            ti.scanTime  = qt.value(6).toString().left(19);
            ti.status    = "待处理";
            d.threats.append(ti);
        }
    }

    // ── 进程风险 ──────────────────────────────────────────────────────────
    {
        QSqlQuery q(db);
        q.exec("SELECT risk,COUNT(*) FROM process_info GROUP BY risk");
        int h=0,m=0,l=0,c=0;
        while(q.next()) {
            QString r=q.value(0).toString(); int n=q.value(1).toInt();
            if(r=="高危") h+=n; else if(r=="中危") m+=n;
            else if(r=="低危") l+=n; else c+=n;
        }
        d.moduleStat["进程检测"] = {h,m,l,c};
        d.totalHigh+=h; d.totalMedium+=m; d.totalLow+=l; d.totalClean+=c;
    }

    // ── 驱动风险 ──────────────────────────────────────────────────────────
    {
        QSqlQuery q(db);
        q.exec("SELECT risk,COUNT(*) FROM driver_info GROUP BY risk");
        int h=0,m=0,l=0,c=0;
        while(q.next()) {
            QString r=q.value(0).toString(); int n=q.value(1).toInt();
            if(r=="high") h+=n; else if(r=="medium") m+=n;
            else if(r=="low") l+=n; else c+=n;
        }
        d.moduleStat["驱动检测"] = {h,m,l,c};
        d.totalHigh+=h; d.totalMedium+=m; d.totalLow+=l; d.totalClean+=c;
    }

    // ── 自启动风险 ────────────────────────────────────────────────────────
    {
        QSqlQuery q(db);
        q.exec("SELECT risk,COUNT(*) FROM autorun_info GROUP BY risk");
        int h=0,m=0,l=0,c=0;
        while(q.next()) {
            QString r=q.value(0).toString(); int n=q.value(1).toInt();
            if(r=="high") h+=n; else if(r=="medium") m+=n;
            else if(r=="low") l+=n; else c+=n;
        }
        d.moduleStat["自启动检测"] = {h,m,l,c};
        d.totalHigh+=h; d.totalMedium+=m; d.totalLow+=l; d.totalClean+=c;
    }

    // ── 证书扫描 ──────────────────────────────────────────────────────────
    {
        QSqlQuery q(db);
        q.exec("SELECT has_signature,signature_valid,file_tampered FROM cert_scan");
        int noSign=0, invalid=0, tampered=0, ok=0;
        while(q.next()) {
            if(q.value(0).toInt()==0) noSign++;
            else if(q.value(1).toInt()==0) invalid++;
            else if(q.value(2).toInt()==1) tampered++;
            else ok++;
        }
        int h=noSign+tampered, m=invalid;
        d.moduleStat["证书扫描"] = {h,m,0,ok};
        d.totalHigh+=h; d.totalMedium+=m; d.totalClean+=ok;
    }

    // ── 处置建议 ──────────────────────────────────────────────────────────
    if (d.totalHigh > 0)
        d.suggestions << QString("发现 %1 个高危威胁，建议立即隔离相关文件并进行深度清除。").arg(d.totalHigh);
    if (d.moduleStat.value("静态扫描").value(0) > 0)
        d.suggestions << "静态扫描发现恶意代码，建议使用专业杀毒工具进行全盘扫描。";
    if (d.moduleStat.value("动态行为").value(0) > 0)
        d.suggestions << "动态行为检测发现高危行为，建议检查相关进程并追踪调用链。";
    if (d.moduleStat.value("文件关联").value(0) > 0)
        d.suggestions << "文件关联被篡改，建议通过注册表恢复正常关联或重装相关软件。";
    if (d.moduleStat.value("端口检测").value(0) > 0)
        d.suggestions << "发现高危端口连接，建议排查相关进程，必要时封堵对应端口。";
    if (d.moduleStat.value("驱动检测").value(0) > 0)
        d.suggestions << "发现未签名驱动，建议验证驱动来源，禁用或卸载可疑驱动。";
    if (d.moduleStat.value("自启动检测").value(0) > 0)
        d.suggestions << "发现高危自启动项，建议清除可疑启动项，防止恶意程序持久化。";
    if (d.moduleStat.value("证书扫描").value(0) > 0)
        d.suggestions << "发现无签名或证书异常文件，建议核实文件来源，谨慎执行。";
    if (d.totalHigh == 0 && d.totalMedium == 0)
        d.suggestions << "当前检测未发现高危或中危威胁，建议保持定期检测习惯。";
}

// ─────────────────────────────────────────────────────────────────────────────
// 填充 UI
// ─────────────────────────────────────────────────────────────────────────────
void ReportPage::fillOverview(const ReportData &d)
{
    m_lblReportId->setText(d.reportId);
    m_lblReportTime->setText(d.reportTime);
    m_lblHostname->setText(d.hostname);
    m_lblOs->setText(d.os);
    m_lblIp->setText(d.ip);
    m_lblCollectTime->setText(d.collectTime.isEmpty() ? d.reportTime : d.collectTime);

    m_cardHighCount->setText(QString::number(d.totalHigh));
    m_cardMediumCount->setText(QString::number(d.totalMedium));
    m_cardLowCount->setText(QString::number(d.totalLow));
    m_cardCleanCount->setText(QString::number(d.totalClean));

    m_tblModuleStat->setRowCount(0);
    QStringList modOrder = {"静态扫描","动态行为","文件关联","端口检测",
                            "进程检测","驱动检测","自启动检测","证书扫描"};
    for (const QString &mod : modOrder) {
        if (!d.moduleStat.contains(mod)) continue;
        const auto &stat = d.moduleStat[mod];
        int h=stat[0], m=stat[1], l=stat[2], c=stat[3], total=h+m+l+c;
        int row = m_tblModuleStat->rowCount();
        m_tblModuleStat->insertRow(row);
        m_tblModuleStat->setItem(row, 0, new QTableWidgetItem(mod));

        auto numItem = [](int n, const QString &color) -> QTableWidgetItem* {
            QTableWidgetItem *it = new QTableWidgetItem(QString::number(n));
            it->setTextAlignment(Qt::AlignCenter);
            if (n > 0) { QFont f=it->font(); f.setBold(true); it->setFont(f); it->setForeground(QColor(color)); }
            return it;
        };
        m_tblModuleStat->setItem(row, 1, numItem(h, "#f5222d"));
        m_tblModuleStat->setItem(row, 2, numItem(m, "#d46b08"));
        m_tblModuleStat->setItem(row, 3, numItem(l, "#0050b3"));
        m_tblModuleStat->setItem(row, 4, numItem(c, "#389e0d"));
        QTableWidgetItem *totItem = new QTableWidgetItem(QString::number(total));
        totItem->setTextAlignment(Qt::AlignCenter);
        m_tblModuleStat->setItem(row, 5, totItem);

        QString status = h>0?"高危":m>0?"中危":l>0?"低危":"正常";
        QTableWidgetItem *stItem = new QTableWidgetItem(status);
        stItem->setTextAlignment(Qt::AlignCenter);
        QFont sf=stItem->font(); sf.setBold(true); stItem->setFont(sf);
        if(h>0){stItem->setForeground(QColor("#f5222d"));stItem->setBackground(QColor("#fff1f0"));}
        else if(m>0){stItem->setForeground(QColor("#d46b08"));stItem->setBackground(QColor("#fffbe6"));}
        else if(l>0){stItem->setForeground(QColor("#0050b3"));stItem->setBackground(QColor("#e6f7ff"));}
        else{stItem->setForeground(QColor("#389e0d"));stItem->setBackground(QColor("#f6ffed"));}
        m_tblModuleStat->setItem(row, 6, stItem);
    }
}

void ReportPage::fillThreatTable(const ReportData &d)
{
    QString kw      = m_edtThreatKw  ? m_edtThreatKw->text().trimmed()  : "";
    QString riskSel = m_cmbThreatRisk ? m_cmbThreatRisk->currentText()  : "全部风险";
    QString catSel  = m_cmbThreatCat  ? m_cmbThreatCat->currentText()   : "全部类别";

    QMap<QString,QString> riskMap = {{"高危","high"},{"中危","medium"},{"低危","low"},{"安全","clean"}};

    m_tblThreats->setRowCount(0);
    int shown = 0;
    for (const ThreatItem &ti : d.threats) {
        if (!kw.isEmpty() && !ti.name.contains(kw,Qt::CaseInsensitive)
                          && !ti.filePath.contains(kw,Qt::CaseInsensitive)
                          && !ti.detail.contains(kw,Qt::CaseInsensitive)) continue;
        if (riskSel != "全部风险" && riskMap.value(riskSel) != ti.riskLevel) continue;
        if (catSel  != "全部类别" && catSel != ti.category) continue;

        int row = m_tblThreats->rowCount();
        m_tblThreats->insertRow(row);
        m_tblThreats->setItem(row, 0, new QTableWidgetItem(ti.name));
        m_tblThreats->setItem(row, 1, riskItem(ti.riskLevel));
        m_tblThreats->setItem(row, 2, new QTableWidgetItem(ti.category));
        QTableWidgetItem *pathItem = new QTableWidgetItem(ti.filePath);
        pathItem->setFont(QFont("Consolas", 11));
        m_tblThreats->setItem(row, 3, pathItem);
        m_tblThreats->setItem(row, 4, new QTableWidgetItem(ti.detail));
        m_tblThreats->setItem(row, 5, new QTableWidgetItem(ti.scanTime));
        QTableWidgetItem *stItem = new QTableWidgetItem(ti.status);
        stItem->setForeground(ti.status=="已隔离" ? QColor("#389e0d") : QColor("#d46b08"));
        m_tblThreats->setItem(row, 6, stItem);
        highlightRow(m_tblThreats, row, ti.riskLevel);
        shown++;
    }
    if (m_lblThreatCount)
        m_lblThreatCount->setText(QString("共 %1 条威胁记录").arg(shown));
}

void ReportPage::fillHostTable(const ReportData &d)
{
    (void)d;
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (!db.isOpen()) return;

    // 系统信息
    m_tblSysInfo->setRowCount(0);
    QStringList sysKeys = {"hostname","os_name","os_version","cpu_model","total_memory",
                           "architecture","computer_type","domain","last_boot","collect_time"};
    QMap<QString,QString> sysLabel = {
        {"hostname","主机名"},{"os_name","操作系统"},{"os_version","系统版本"},
        {"cpu_model","CPU 型号"},{"total_memory","内存总量"},{"architecture","系统架构"},
        {"computer_type","计算机类型"},{"domain","域/工作组"},
        {"last_boot","最后启动时间"},{"collect_time","数据采集时间"}
    };
    for (const QString &k : sysKeys) {
        QSqlQuery q(db);
        q.prepare("SELECT value FROM sys_info WHERE key=? LIMIT 1");
        q.addBindValue(k);
        if (!q.exec() || !q.next()) continue;
        int row = m_tblSysInfo->rowCount();
        m_tblSysInfo->insertRow(row);
        m_tblSysInfo->setItem(row, 0, new QTableWidgetItem(sysLabel.value(k, k)));
        m_tblSysInfo->setItem(row, 1, new QTableWidgetItem(q.value(0).toString()));
    }

    // 网络信息
    m_tblNetInfo->setRowCount(0);
    {
        QSqlQuery q(db);
        q.exec("SELECT name,ip,mask,gateway,mac,status FROM net_info ORDER BY id");
        while(q.next()) {
            int row = m_tblNetInfo->rowCount();
            m_tblNetInfo->insertRow(row);
            for(int c=0;c<6;c++) m_tblNetInfo->setItem(row,c,new QTableWidgetItem(q.value(c).toString()));
            if(q.value(5).toString()=="已连接")
                for(int c=0;c<6;c++) if(m_tblNetInfo->item(row,c))
                    m_tblNetInfo->item(row,c)->setBackground(QColor("#f6ffed"));
        }
    }

    // 磁盘信息
    m_tblDiskInfo->setRowCount(0);
    {
        QSqlQuery q(db);
        q.exec("SELECT drive,type,filesystem,total_gb,free_gb,used_pct FROM disk_info ORDER BY id");
        while(q.next()) {
            int row = m_tblDiskInfo->rowCount();
            m_tblDiskInfo->insertRow(row);
            for(int c=0;c<5;c++) m_tblDiskInfo->setItem(row,c,new QTableWidgetItem(q.value(c).toString()));
            QString pct = q.value(5).toString();
            QTableWidgetItem *pi = new QTableWidgetItem(pct);
            if(pct.remove("%").toDouble() >= 80) {
                pi->setForeground(QColor("#f5222d"));
                QFont f=pi->font(); f.setBold(true); pi->setFont(f);
            }
            m_tblDiskInfo->setItem(row,5,pi);
        }
    }

    // 高风险进程
    m_tblProcRisk->setRowCount(0);
    {
        QSqlQuery q(db);
        q.exec("SELECT pid,name,path,user,cpu_pct,mem_mb,risk FROM process_info "
               "WHERE risk IN ('高危','中危') "
               "ORDER BY CASE risk WHEN '高危' THEN 0 ELSE 1 END, cpu_pct DESC");
        while(q.next()) {
            int row = m_tblProcRisk->rowCount();
            m_tblProcRisk->insertRow(row);
            for(int c=0;c<7;c++) m_tblProcRisk->setItem(row,c,new QTableWidgetItem(q.value(c).toString()));
            if(q.value(6).toString()=="高危")
                for(int c=0;c<7;c++) if(m_tblProcRisk->item(row,c))
                    m_tblProcRisk->item(row,c)->setBackground(QColor("#fff1f0"));
        }
    }

    // 高风险端口
    m_tblPortRisk->setRowCount(0);
    {
        QSqlQuery q(db);
        q.exec("SELECT protocol,local_ip,local_port,remote_ip,remote_port,process_name,risk "
               "FROM port_info WHERE risk IN ('high','medium') "
               "ORDER BY CASE risk WHEN 'high' THEN 0 ELSE 1 END, id");
        while(q.next()) {
            int row = m_tblPortRisk->rowCount();
            m_tblPortRisk->insertRow(row);
            for(int c=0;c<6;c++) m_tblPortRisk->setItem(row,c,new QTableWidgetItem(q.value(c).toString()));
            m_tblPortRisk->setItem(row,6,riskItem(q.value(6).toString()));
            if(q.value(6).toString()=="high")
                for(int c=0;c<7;c++) if(m_tblPortRisk->item(row,c))
                    m_tblPortRisk->item(row,c)->setBackground(QColor("#fff1f0"));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 报告预览
// ─────────────────────────────────────────────────────────────────────────────
void ReportPage::buildPreview(const ReportData &d)
{
    m_txtPreview->setHtml(buildHtmlReport(d));
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML 报告
// ─────────────────────────────────────────────────────────────────────────────
QString ReportPage::buildHtmlReport(const ReportData &d)
{
    QString riskBadge, riskText;
    if (d.totalHigh>0)   { riskBadge="badge-high";   riskText="高危"; }
    else if (d.totalMedium>0) { riskBadge="badge-medium"; riskText="中危"; }
    else if (d.totalLow>0)   { riskBadge="badge-low";    riskText="低危"; }
    else                      { riskBadge="badge-clean";  riskText="安全"; }

    QString html;
    html += "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n"
            "<meta charset=\"UTF-8\">\n"
            "<title>恶意代码辅助检测分析报告</title>\n"
            "<style>\n"
            "*{box-sizing:border-box;margin:0;padding:0;}\n"
            "body{font-family:\"Microsoft YaHei\",\"SimHei\",Arial,sans-serif;"
            "font-size:13px;color:#262626;background:#f5f7fa;padding:0;}\n"
            ".page{max-width:960px;margin:0 auto;background:#fff;"
            "padding:40px 50px;box-shadow:0 2px 8px rgba(0,0,0,.12);}\n"
            ".cover{text-align:center;padding:60px 0 40px;}\n"
            ".cover-logo{font-size:36px;font-weight:700;color:#1a3a6a;"
            "letter-spacing:4px;margin-bottom:8px;}\n"
            ".cover-sub{font-size:14px;color:#595959;margin-bottom:40px;}\n"
            ".cover-title{font-size:28px;font-weight:700;color:#1a3a6a;"
            "border-bottom:3px solid #1a3a6a;display:inline-block;"
            "padding-bottom:8px;margin-bottom:30px;}\n"
            ".cover-meta{display:inline-block;text-align:left;background:#f5f7fa;"
            "border:1px solid #d0d7e3;border-radius:6px;padding:16px 30px;min-width:360px;}\n"
            ".cover-meta tr td{padding:5px 12px;font-size:13px;}\n"
            ".cover-meta tr td:first-child{color:#595959;font-weight:600;white-space:nowrap;}\n"
            ".section{margin:28px 0 0;}\n"
            ".section-title{font-size:16px;font-weight:700;color:#1a3a6a;"
            "border-left:4px solid #1a3a6a;padding-left:10px;margin-bottom:14px;}\n"
            ".subsection-title{font-size:13px;font-weight:700;color:#434343;"
            "border-left:3px solid #91caff;padding-left:8px;margin:14px 0 8px;}\n"
            ".risk-cards{display:flex;gap:16px;margin:14px 0;}\n"
            ".risk-card{flex:1;border-radius:6px;padding:14px 10px;text-align:center;}\n"
            ".risk-card .count{font-size:32px;font-weight:700;}\n"
            ".risk-card .label{font-size:11px;margin-top:4px;font-weight:600;}\n"
            ".card-high{background:#fff1f0;color:#f5222d;}\n"
            ".card-medium{background:#fffbe6;color:#d46b08;}\n"
            ".card-low{background:#e6f7ff;color:#0050b3;}\n"
            ".card-clean{background:#f6ffed;color:#389e0d;}\n"
            ".badge{display:inline-block;padding:2px 8px;border-radius:10px;"
            "font-size:11px;font-weight:600;}\n"
            ".badge-high{background:#fff1f0;color:#f5222d;}\n"
            ".badge-medium{background:#fffbe6;color:#d46b08;}\n"
            ".badge-low{background:#e6f7ff;color:#0050b3;}\n"
            ".badge-clean{background:#f6ffed;color:#389e0d;}\n"
            "table.report-table{width:100%;border-collapse:collapse;margin:8px 0;font-size:12px;}\n"
            "table.report-table th{background:#e8ecf4;padding:7px 10px;"
            "border:1px solid #d0d7e3;font-weight:600;text-align:left;}\n"
            "table.report-table td{padding:6px 10px;border:1px solid #d0d7e3;vertical-align:top;}\n"
            "table.report-table tr:nth-child(even) td{background:#fafbfd;}\n"
            "table.report-table tr.row-high td{background:#fff1f0;}\n"
            "table.report-table tr.row-medium td{background:#fffbe6;}\n"
            ".suggestion-list{background:#f5f7fa;border:1px solid #d0d7e3;"
            "border-radius:4px;padding:12px 16px;margin:8px 0;}\n"
            ".suggestion-list li{margin:6px 0;line-height:1.7;font-size:12px;}\n"
            ".footer{margin-top:40px;padding-top:16px;border-top:1px solid #d0d7e3;"
            "text-align:center;color:#8c8c8c;font-size:11px;}\n"
            "</style>\n</head>\n<body>\n<div class=\"page\">\n";

    // 封面
    html += "<div class=\"cover\">\n"
            "<div class=\"cover-logo\">SecureDetect</div>\n"
            "<div class=\"cover-sub\">恶意代码辅助检测系统</div>\n"
            "<div class=\"cover-title\">检测分析报告</div><br>\n"
            "<table class=\"cover-meta\">\n";
    html += "<tr><td>报告编号：</td><td>" + escHtml(d.reportId) + "</td></tr>\n";
    html += "<tr><td>生成时间：</td><td>" + escHtml(d.reportTime) + "</td></tr>\n";
    html += "<tr><td>检测主机：</td><td>" + escHtml(d.hostname) + "</td></tr>\n";
    html += "<tr><td>操作系统：</td><td>" + escHtml(d.os) + "</td></tr>\n";
    html += "<tr><td>IP 地址：</td><td>"  + escHtml(d.ip) + "</td></tr>\n";
    html += "<tr><td>综合风险：</td><td><span class=\"badge " + riskBadge + "\">" + riskText + "</span></td></tr>\n";
    html += "<tr><td>分析人员：</td><td>" + escHtml(d.analyst) + "</td></tr>\n";
    html += "</table>\n</div>\n";

    // 第一章：风险概览
    html += "<div class=\"section\">\n<div class=\"section-title\">一、风险概览</div>\n";
    html += "<div class=\"risk-cards\">\n";
    html += "<div class=\"risk-card card-high\"><div class=\"count\">" + QString::number(d.totalHigh) +
            "</div><div class=\"label\">高危威胁</div></div>\n";
    html += "<div class=\"risk-card card-medium\"><div class=\"count\">" + QString::number(d.totalMedium) +
            "</div><div class=\"label\">中危威胁</div></div>\n";
    html += "<div class=\"risk-card card-low\"><div class=\"count\">" + QString::number(d.totalLow) +
            "</div><div class=\"label\">低危威胁</div></div>\n";
    html += "<div class=\"risk-card card-clean\"><div class=\"count\">" + QString::number(d.totalClean) +
            "</div><div class=\"label\">安全项目</div></div>\n";
    html += "</div>\n";

    html += "<div class=\"subsection-title\">各模块风险分布</div>\n";
    html += "<table class=\"report-table\">\n"
            "<tr><th>检测模块</th><th>高危</th><th>中危</th><th>低危</th>"
            "<th>安全/正常</th><th>合计</th><th>风险状态</th></tr>\n";
    QStringList modOrder = {"静态扫描","动态行为","文件关联","端口检测",
                            "进程检测","驱动检测","自启动检测","证书扫描"};
    for (const QString &mod : modOrder) {
        if (!d.moduleStat.contains(mod)) continue;
        const auto &stat = d.moduleStat[mod];
        int h=stat[0],m=stat[1],l=stat[2],c=stat[3],total=h+m+l+c;
        QString rowClass = h>0?" class=\"row-high\"":m>0?" class=\"row-medium\"":"";
        QString status = h>0?"<span class=\"badge badge-high\">高危</span>":
                         m>0?"<span class=\"badge badge-medium\">中危</span>":
                         l>0?"<span class=\"badge badge-low\">低危</span>":
                         "<span class=\"badge badge-clean\">正常</span>";
        html += "<tr" + rowClass + ">"
                "<td>" + escHtml(mod) + "</td>"
                "<td style='color:#f5222d;font-weight:600;text-align:center'>" + QString::number(h) + "</td>"
                "<td style='color:#d46b08;font-weight:600;text-align:center'>" + QString::number(m) + "</td>"
                "<td style='color:#0050b3;font-weight:600;text-align:center'>" + QString::number(l) + "</td>"
                "<td style='color:#389e0d;font-weight:600;text-align:center'>" + QString::number(c) + "</td>"
                "<td style='text-align:center'>" + QString::number(total) + "</td>"
                "<td style='text-align:center'>" + status + "</td></tr>\n";
    }
    html += "</table>\n</div>\n";

    // 第二章：主机信息
    html += "<div class=\"section\">\n<div class=\"section-title\">二、主机基本信息</div>\n";
    html += "<table class=\"report-table\">\n<tr><th style=\"width:180px\">项目</th><th>值</th></tr>\n";
    QMap<QString,QString> sysLabelMap = {
        {"hostname","主机名"},{"os_name","操作系统"},{"os_version","系统版本"},
        {"cpu_model","CPU 型号"},{"total_memory","内存总量"},{"architecture","系统架构"},
        {"computer_type","计算机类型"},{"domain","域/工作组"},
        {"last_boot","最后启动时间"},{"collect_time","数据采集时间"}
    };
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QStringList sysKeys = {"hostname","os_name","os_version","cpu_model","total_memory",
                               "architecture","computer_type","domain","last_boot","collect_time"};
        for (const QString &k : sysKeys) {
            QSqlQuery q(db);
            q.prepare("SELECT value FROM sys_info WHERE key=? LIMIT 1");
            q.addBindValue(k);
            if (q.exec() && q.next())
                html += "<tr><td>" + escHtml(sysLabelMap.value(k,k)) + "</td>"
                        "<td>" + escHtml(q.value(0).toString()) + "</td></tr>\n";
        }
    }
    html += "</table>\n</div>\n";

    // 第三章：恶意代码检测结果
    html += "<div class=\"section\">\n<div class=\"section-title\">三、恶意代码检测结果</div>\n";
    if (d.threats.isEmpty()) {
        html += "<p style='color:#389e0d;font-weight:600;padding:12px;'>未发现恶意代码威胁。</p>\n";
    } else {
        html += "<table class=\"report-table\">\n"
                "<tr><th>威胁名称</th><th>风险等级</th><th>威胁类别</th>"
                "<th>文件路径</th><th>详细信息</th><th>发现时间</th><th>处置状态</th></tr>\n";
        for (const ThreatItem &ti : d.threats) {
            QString rowClass = ti.riskLevel=="high"?" class=\"row-high\"":
                               ti.riskLevel=="medium"?" class=\"row-medium\"":"";
            QString badgeClass = ti.riskLevel=="high"?"badge-high":
                                 ti.riskLevel=="medium"?"badge-medium":
                                 ti.riskLevel=="low"?"badge-low":"badge-clean";
            QString riskZh = ti.riskLevel=="high"?"高危":ti.riskLevel=="medium"?"中危":
                             ti.riskLevel=="low"?"低危":"安全";
            html += "<tr" + rowClass + ">"
                    "<td>" + escHtml(ti.name) + "</td>"
                    "<td><span class=\"badge " + badgeClass + "\">" + riskZh + "</span></td>"
                    "<td>" + escHtml(ti.category) + "</td>"
                    "<td style='font-family:Consolas,monospace;font-size:11px;'>" + escHtml(ti.filePath) + "</td>"
                    "<td>" + escHtml(ti.detail) + "</td>"
                    "<td>" + escHtml(ti.scanTime) + "</td>"
                    "<td style='color:" + QString(ti.status=="已隔离"?"#389e0d":"#d46b08") +
                    ";font-weight:600;'>" + escHtml(ti.status) + "</td></tr>\n";
        }
        html += "</table>\n";
    }
    html += "</div>\n";

    // 第四章：处置建议
    html += "<div class=\"section\">\n<div class=\"section-title\">四、处置建议</div>\n"
            "<ul class=\"suggestion-list\">\n";
    for (const QString &s : d.suggestions)
        html += "<li>" + escHtml(s) + "</li>\n";
    html += "</ul>\n</div>\n";

    // 页脚
    html += "<div class=\"footer\">\n"
            "本报告由恶意代码辅助检测系统自动生成 &nbsp;|&nbsp; 报告编号：" + escHtml(d.reportId) +
            " &nbsp;|&nbsp; 生成时间：" + escHtml(d.reportTime) + "<br>\n"
            "报告内容仅供参考，最终处置决策请结合实际情况由专业人员判断。\n"
            "</div>\n</div>\n</body>\n</html>\n";

    return html;
}

// ─────────────────────────────────────────────────────────────────────────────
// RTF 报告（DOC 格式）
// ─────────────────────────────────────────────────────────────────────────────
QString ReportPage::buildRtfReport(const ReportData &d)
{
    // RTF Unicode 编码辅助
    auto u = [](const QString &s) -> QString {
        QString out;
        for (QChar c : s) {
            ushort code = c.unicode();
            if (code > 127) out += "\\u" + QString::number((short)code) + "?";
            else out += c;
        }
        return out;
    };

    QString rtf;
    rtf += "{\\rtf1\\ansi\\ansicpg936\\deff0\n"
           "{\\fonttbl{\\f0\\fnil\\fcharset134 Microsoft YaHei;}}\n"
           "{\\colortbl;\\red26\\green58\\blue106;\\red245\\green34\\blue45;"
           "\\red212\\green107\\blue8;\\red0\\green80\\blue179;\\red56\\green158\\blue13;}\n"
           "\\paperw12240\\paperh15840\\margl1800\\margr1800\\margt1440\\margb1440\n";

    // 标题
    rtf += "\\pard\\qc{\\f0\\fs40\\b\\cf1 " + u("恶意代码辅助检测分析报告") + "\\par}\n";
    rtf += "\\pard\\qc{\\f0\\fs22 " + u("SecureDetect 恶意代码辅助检测系统") + "\\par}\n";
    rtf += "\\pard\\qc{\\f0\\fs20 " + u("报告编号：") + u(d.reportId) +
           "  " + u("生成时间：") + u(d.reportTime) + "\\par}\n";
    rtf += "\\pard\\qc{\\f0\\fs20 " + u("检测主机：") + u(d.hostname) +
           "  " + u("IP：") + u(d.ip) + "\\par}\n\\pard\\par\n";

    // 第一章
    rtf += "\\pard{\\f0\\fs28\\b\\cf1 " + u("一、风险概览") + "\\par}\n";
    rtf += "\\pard{\\f0\\fs22 " +
           u("高危威胁：") + "{\\cf2\\b " + QString::number(d.totalHigh) + "}  " +
           u("中危威胁：") + "{\\cf3\\b " + QString::number(d.totalMedium) + "}  " +
           u("低危威胁：") + "{\\cf4\\b " + QString::number(d.totalLow) + "}  " +
           u("安全项目：") + "{\\cf5\\b " + QString::number(d.totalClean) + "}\\par}\n";
    rtf += "\\pard\\par\n";

    rtf += "\\pard{\\f0\\fs24\\b " + u("各模块风险分布") + "\\par}\n";
    QStringList modOrder = {"静态扫描","动态行为","文件关联","端口检测",
                            "进程检测","驱动检测","自启动检测","证书扫描"};
    for (const QString &mod : modOrder) {
        if (!d.moduleStat.contains(mod)) continue;
        const auto &stat = d.moduleStat[mod];
        rtf += "\\pard{\\f0\\fs20 " + u(mod) +
               u("：高危 ") + QString::number(stat[0]) +
               u(" 中危 ") + QString::number(stat[1]) +
               u(" 低危 ") + QString::number(stat[2]) +
               u(" 安全 ") + QString::number(stat[3]) + "\\par}\n";
    }
    rtf += "\\pard\\par\n";

    // 第二章
    rtf += "\\pard{\\f0\\fs28\\b\\cf1 " + u("二、主机基本信息") + "\\par}\n";
    rtf += "\\pard{\\f0\\fs20 " + u("主机名：") + u(d.hostname) +
           "  " + u("操作系统：") + u(d.os) +
           "  " + u("IP：") + u(d.ip) + "\\par}\n\\pard\\par\n";

    // 第三章
    rtf += "\\pard{\\f0\\fs28\\b\\cf1 " + u("三、恶意代码检测结果") + "\\par}\n";
    if (d.threats.isEmpty()) {
        rtf += "\\pard{\\f0\\fs20\\cf5 " + u("未发现恶意代码威胁。") + "\\par}\n";
    } else {
        for (const ThreatItem &ti : d.threats) {
            QString riskZh = ti.riskLevel=="high"?"高危":ti.riskLevel=="medium"?"中危":
                             ti.riskLevel=="low"?"低危":"安全";
            int cf = ti.riskLevel=="high"?2:ti.riskLevel=="medium"?3:ti.riskLevel=="low"?4:5;
            rtf += "\\pard{\\f0\\fs20 " + u(ti.name) +
                   "  [{\\cf" + QString::number(cf) + "\\b " + u(riskZh) + "}]  " +
                   u(ti.category) + "  " + u(ti.filePath) + "\\par}\n";
        }
    }
    rtf += "\\pard\\par\n";

    // 第四章
    rtf += "\\pard{\\f0\\fs28\\b\\cf1 " + u("四、处置建议") + "\\par}\n";
    int idx = 1;
    for (const QString &s : d.suggestions)
        rtf += "\\pard{\\f0\\fs20 " + QString::number(idx++) + ". " + u(s) + "\\par}\n";

    rtf += "}\n";
    return rtf;
}

// ─────────────────────────────────────────────────────────────────────────────
// Slots
// ─────────────────────────────────────────────────────────────────────────────
void ReportPage::refreshData()
{
    onGenerateReport();
}

void ReportPage::onGenerateReport()
{
    collectData(m_lastData);
    m_dataReady = true;
    fillOverview(m_lastData);
    fillThreatTable(m_lastData);
    fillHostTable(m_lastData);
    buildPreview(m_lastData);
    m_lblStatus->setText("报告已生成：" + m_lastData.reportTime);
    DatabaseManager::instance()->writeLog(m_role, m_username, "生成检测报告",
                                          m_lastData.reportId, "success");
    // 写入历史库
    saveToHistory(m_lastData,
                  buildHtmlReport(m_lastData),
                  buildRtfReport(m_lastData),
                  "手动生成");
}

void ReportPage::onQueryThreats()
{
    if (m_dataReady) fillThreatTable(m_lastData);
}

void ReportPage::onExportHtml()
{
    if (!m_dataReady) { QMessageBox::warning(this,"提示","请先点击\"生成报告\""); return; }
    QString path = QFileDialog::getSaveFileName(this, "导出 HTML 报告",
        "检测报告_" + QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".html",
        "HTML 文件 (*.html)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this,"错误","无法写入文件：" + path); return;
    }
    QTextStream ts(&f);
    ts.setCodec("UTF-8");
    ts << buildHtmlReport(m_lastData);
    f.close();
    QMessageBox::information(this,"导出成功","HTML 报告已保存至：\n" + path);
    DatabaseManager::instance()->writeLog(m_role, m_username, "导出HTML报告", path, "success");
}

void ReportPage::onExportPdf()
{
    if (!m_dataReady) { QMessageBox::warning(this,"提示","请先点击\"生成报告\""); return; }
    QString path = QFileDialog::getSaveFileName(this, "导出 PDF 报告",
        "检测报告_" + QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".pdf",
        "PDF 文件 (*.pdf)");
    if (path.isEmpty()) return;

    QPrinter printer(QPrinter::HighResolution);
    printer.setOutputFormat(QPrinter::PdfFormat);
    printer.setOutputFileName(path);
    printer.setPageSize(QPrinter::A4);
    printer.setPageMargins(15, 15, 15, 15, QPrinter::Millimeter);

    QTextDocument doc;
    doc.setDefaultFont(QFont("Microsoft YaHei", 10));
    doc.setHtml(buildHtmlReport(m_lastData));
    doc.print(&printer);

    QMessageBox::information(this,"导出成功","PDF 报告已保存至：\n" + path);
    DatabaseManager::instance()->writeLog(m_role, m_username, "导出PDF报告", path, "success");
}

void ReportPage::onExportDoc()
{
    if (!m_dataReady) { QMessageBox::warning(this,"提示","请先点击\"生成报告\""); return; }
    QString path = QFileDialog::getSaveFileName(this, "导出 DOC 报告",
        "检测报告_" + QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".rtf",
        "RTF 文档 (*.rtf);;Word 文档 (*.doc)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) {
        QMessageBox::critical(this,"错误","无法写入文件：" + path); return;
    }
    f.write(buildRtfReport(m_lastData).toLocal8Bit());
    f.close();
    QMessageBox::information(this,"导出成功",
        "DOC/RTF 报告已保存至：\n" + path + "\n（可用 Word、WPS 等软件打开）");
    DatabaseManager::instance()->writeLog(m_role, m_username, "导出DOC报告", path, "success");
}

void ReportPage::onTimerToggle(bool checked)
{
    m_cmbTimerMode->setEnabled(checked);
    m_spnTimerHour->setEnabled(checked);
    if (m_spnTimerMinute) m_spnTimerMinute->setEnabled(checked);
    if (!checked) {
        m_timer->stop();
        m_nextFireTime = QDateTime();
        m_lblNextTime->setText("--");
        m_lblTimerStatus->setText("定时生成未启用");
        return;
    }
    QStringList modes = {"每天","每周一","每周五","每小时"};
    QString mode = modes.value(m_cmbTimerMode->currentIndex(), "每天");
    int hour   = m_spnTimerHour->value();
    int minute = m_spnTimerMinute ? m_spnTimerMinute->value() : 0;
    m_nextFireTime = calcNextFire(mode, hour, minute);
    m_lblNextTime->setText(m_nextFireTime.toString("yyyy-MM-dd HH:mm:ss"));
    m_lblTimerStatus->setText("定时生成已启用，等待触发...");

    qint64 msecs = QDateTime::currentDateTime().msecsTo(m_nextFireTime);
    m_timer->setSingleShot(true);
    m_timer->start(static_cast<int>(qMin(msecs, (qint64)INT_MAX)));
}

void ReportPage::onTimerFired()
{
    // 重新收集数据并生成报告
    collectData(m_lastData);
    m_dataReady = true;
    fillOverview(m_lastData);
    fillThreatTable(m_lastData);
    fillHostTable(m_lastData);
    buildPreview(m_lastData);

    QString htmlContent = buildHtmlReport(m_lastData);
    QString rtfContent  = buildRtfReport(m_lastData);

    // 写入历史库（定时触发）
    saveToHistory(m_lastData, htmlContent, rtfContent, "定时自动");

    // 自动导出 HTML 到用户目录
    QString path = QDir::homePath() + "/检测报告_" +
                   QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".html";
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream ts(&f);
        ts.setCodec("UTF-8");
        ts << htmlContent;
        f.close();
    }
    m_lblStatus->setText("定时报告已生成：" + m_lastData.reportTime);
    m_lblTimerStatus->setText("已自动生成报告：" +
                              QDateTime::currentDateTime().toString("HH:mm:ss"));
    DatabaseManager::instance()->writeLog(m_role, m_username, "定时生成检测报告",
                                          m_lastData.reportId, "success");
    // 重新设置下一次定时
    if (m_chkTimerEnable->isChecked()) onTimerToggle(true);
}

// ── 报告历史 Tab ──────────────────────────────────────────────────────────────
void ReportPage::setupHistoryTab(QWidget *tab)
{
    QVBoxLayout *lay = new QVBoxLayout(tab);
    lay->setContentsMargins(12,12,12,12);
    lay->setSpacing(8);

    QString gbStyle = "QGroupBox{font-weight:600;font-size:12px;border:1px solid #d0d7e3;"
                      "border-radius:4px;margin-top:8px;padding-top:8px;}"
                      "QGroupBox::title{subcontrol-origin:margin;left:8px;padding:0 4px;}";

    // 工具栏
    QHBoxLayout *bar = new QHBoxLayout;
    bar->setSpacing(8);
    auto makeBtn2 = [](const QString &text, const QString &bg) -> QPushButton* {
        QPushButton *b = new QPushButton(text);
        b->setFixedHeight(28);
        b->setStyleSheet(QString(
            "QPushButton{background:%1;color:#fff;border:none;border-radius:3px;"
            "padding:4px 12px;font-size:12px;font-weight:600;}"
            "QPushButton:hover{opacity:0.85;}").arg(bg));
        return b;
    };
    m_btnExportHistHtml = makeBtn2("导出 HTML", "#0050b3");
    m_btnExportHistDoc  = makeBtn2("导出 DOC",  "#434343");
    m_btnExportHistPdf  = makeBtn2("导出 PDF",  "#003a8c");
    m_btnDeleteHist     = makeBtn2("删除记录",  "#cf1322");
    QPushButton *btnRefresh = makeBtn2("刷新列表", "#1a3a6a");

    m_btnExportHistHtml->setEnabled(false);
    m_btnExportHistDoc->setEnabled(false);
    m_btnExportHistPdf->setEnabled(false);
    m_btnDeleteHist->setEnabled(false);

    connect(m_btnExportHistHtml, &QPushButton::clicked, this, &ReportPage::onExportHistoryHtml);
    connect(m_btnExportHistDoc,  &QPushButton::clicked, this, &ReportPage::onExportHistoryDoc);
    connect(m_btnExportHistPdf,  &QPushButton::clicked, this, &ReportPage::onExportHistoryPdf);
    connect(m_btnDeleteHist,     &QPushButton::clicked, this, &ReportPage::onDeleteHistory);
    connect(btnRefresh,          &QPushButton::clicked, this, &ReportPage::refreshHistory);

    bar->addWidget(btnRefresh);
    bar->addWidget(m_btnExportHistHtml);
    bar->addWidget(m_btnExportHistDoc);
    bar->addWidget(m_btnExportHistPdf);
    bar->addWidget(m_btnDeleteHist);
    bar->addStretch();
    lay->addLayout(bar);

    // 历史列表表格
    m_tblHistory = makeTable({"ID","报告编号","生成时间","触发方式","主机名",
                               "高危","中危","低危","安全"});
    m_tblHistory->setSelectionMode(QAbstractItemView::SingleSelection);
    connect(m_tblHistory, &QTableWidget::itemSelectionChanged,
            this, &ReportPage::onHistorySelectionChanged);
    lay->addWidget(m_tblHistory, 3);

    // 选中记录详情
    QGroupBox *gbDetail = new QGroupBox("选中报告摘要");
    gbDetail->setStyleSheet(gbStyle);
    QVBoxLayout *detLay = new QVBoxLayout(gbDetail);
    m_lblHistDetail = new QLabel("请在列表中选择一条记录");
    m_lblHistDetail->setStyleSheet("font-size:12px;color:#595959;padding:4px;");
    m_lblHistDetail->setWordWrap(true);
    detLay->addWidget(m_lblHistDetail);
    lay->addWidget(gbDetail, 1);

    // 初始加载
    refreshHistory();
}

// ── 历史列表刷新 ──────────────────────────────────────────────────────────────
void ReportPage::refreshHistory()
{
    if (!m_tblHistory) return;
    auto rows = DatabaseManager::instance()->queryReportHistory(50);
    m_tblHistory->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = m_tblHistory->rowCount();
        m_tblHistory->insertRow(row);
        auto setCell = [&](int col, const QString &text, Qt::Alignment align = Qt::AlignLeft | Qt::AlignVCenter) {
            QTableWidgetItem *item = new QTableWidgetItem(text);
            item->setTextAlignment(align);
            m_tblHistory->setItem(row, col, item);
        };
        setCell(0, QString::number(m["id"].toInt()), Qt::AlignCenter | Qt::AlignVCenter);
        setCell(1, m["report_id"].toString());
        setCell(2, m["generate_time"].toString());
        setCell(3, m["trigger_mode"].toString(), Qt::AlignCenter | Qt::AlignVCenter);
        setCell(4, m["hostname"].toString());
        // 风险数字带颜色
        auto riskCell = [&](int col, const QString &key, const QString &color) {
            QTableWidgetItem *item = new QTableWidgetItem(m[key].toString());
            item->setTextAlignment(Qt::AlignCenter | Qt::AlignVCenter);
            QFont f = item->font(); f.setBold(true); item->setFont(f);
            item->setForeground(QColor(color));
            m_tblHistory->setItem(row, col, item);
        };
        riskCell(5, "risk_high",   "#f5222d");
        riskCell(6, "risk_medium", "#fa8c16");
        riskCell(7, "risk_low",    "#1890ff");
        riskCell(8, "risk_clean",  "#52c41a");
    }
    m_lblHistDetail->setText(rows.isEmpty()
        ? "暂无历史报告记录，点击\"生成报告\"后将自动入库。"
        : QString("共 %1 条历史报告，点击行可选中后导出或删除。").arg(rows.size()));
}

// ── 历史列表选中 ──────────────────────────────────────────────────────────────
void ReportPage::onHistorySelectionChanged()
{
    int row = m_tblHistory->currentRow();
    bool hasRow = (row >= 0);
    m_btnExportHistHtml->setEnabled(hasRow);
    m_btnExportHistDoc->setEnabled(hasRow);
    m_btnExportHistPdf->setEnabled(hasRow);
    m_btnDeleteHist->setEnabled(hasRow);
    if (!hasRow) return;

    int id = m_tblHistory->item(row, 0)->text().toInt();
    QVariantMap rec = DatabaseManager::instance()->getReportHistoryById(id);
    m_lblHistDetail->setText(
        QString("报告编号：%1　生成时间：%2　触发方式：%3\n"
                "主机：%4　高危：%5　中危：%6　低危：%7　安全：%8")
        .arg(rec["report_id"].toString())
        .arg(rec["generate_time"].toString())
        .arg(rec["trigger_mode"].toString())
        .arg(rec["hostname"].toString())
        .arg(rec["risk_high"].toInt())
        .arg(rec["risk_medium"].toInt())
        .arg(rec["risk_low"].toInt())
        .arg(rec["risk_clean"].toInt()));
}

// ── 历史导出 HTML ─────────────────────────────────────────────────────────────
void ReportPage::onExportHistoryHtml()
{
    int row = m_tblHistory->currentRow();
    if (row < 0) return;
    int id = m_tblHistory->item(row, 0)->text().toInt();
    QVariantMap rec = DatabaseManager::instance()->getReportHistoryById(id);
    QString html = rec["html_content"].toString();
    if (html.isEmpty()) { QMessageBox::warning(this,"提示","该记录无 HTML 内容"); return; }

    QString path = QFileDialog::getSaveFileName(this, "导出历史 HTML 报告",
        "历史报告_" + rec["report_id"].toString() + ".html",
        "HTML 文件 (*.html)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this,"错误","无法写入文件：" + path); return;
    }
    QTextStream ts(&f); ts.setCodec("UTF-8"); ts << html; f.close();
    QMessageBox::information(this,"导出成功","HTML 报告已保存至：\n" + path);
}

// ── 历史导出 DOC ──────────────────────────────────────────────────────────────
void ReportPage::onExportHistoryDoc()
{
    int row = m_tblHistory->currentRow();
    if (row < 0) return;
    int id = m_tblHistory->item(row, 0)->text().toInt();
    QVariantMap rec = DatabaseManager::instance()->getReportHistoryById(id);
    QString rtf = rec["rtf_content"].toString();
    if (rtf.isEmpty()) { QMessageBox::warning(this,"提示","该记录无 RTF 内容"); return; }

    QString path = QFileDialog::getSaveFileName(this, "导出历史 DOC 报告",
        "历史报告_" + rec["report_id"].toString() + ".rtf",
        "RTF 文档 (*.rtf);;Word 文档 (*.doc)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) {
        QMessageBox::critical(this,"错误","无法写入文件：" + path); return;
    }
    f.write(rtf.toLocal8Bit()); f.close();
    QMessageBox::information(this,"导出成功","DOC/RTF 报告已保存至：\n" + path);
}

// ── 历史导出 PDF ──────────────────────────────────────────────────────────────
void ReportPage::onExportHistoryPdf()
{
    int row = m_tblHistory->currentRow();
    if (row < 0) return;
    int id = m_tblHistory->item(row, 0)->text().toInt();
    QVariantMap rec = DatabaseManager::instance()->getReportHistoryById(id);
    QString html = rec["html_content"].toString();
    if (html.isEmpty()) { QMessageBox::warning(this,"提示","该记录无 HTML 内容，无法导出 PDF"); return; }

    QString path = QFileDialog::getSaveFileName(this, "导出历史 PDF 报告",
        "历史报告_" + rec["report_id"].toString() + ".pdf",
        "PDF 文件 (*.pdf)");
    if (path.isEmpty()) return;

    QPrinter printer(QPrinter::HighResolution);
    printer.setOutputFormat(QPrinter::PdfFormat);
    printer.setOutputFileName(path);
    printer.setPageSize(QPrinter::A4);
    printer.setPageMargins(15, 15, 15, 15, QPrinter::Millimeter);
    QTextDocument doc;
    doc.setDefaultFont(QFont("Microsoft YaHei", 10));
    doc.setHtml(html);
    doc.print(&printer);
    QMessageBox::information(this,"导出成功","PDF 报告已保存至：\n" + path);
}

// ── 删除历史记录 ──────────────────────────────────────────────────────────────
void ReportPage::onDeleteHistory()
{
    int row = m_tblHistory->currentRow();
    if (row < 0) return;
    int id = m_tblHistory->item(row, 0)->text().toInt();
    QString reportId = m_tblHistory->item(row, 1)->text();
    if (QMessageBox::question(this, "确认删除",
            QString("确认删除报告 %1？\n此操作不可恢复。").arg(reportId),
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;
    DatabaseManager::instance()->deleteReportHistory(id);
    refreshHistory();
}

// ── 保存报告到历史库 ──────────────────────────────────────────────────────────
void ReportPage::saveToHistory(const ReportData &d,
                                const QString &htmlContent,
                                const QString &rtfContent,
                                const QString &triggerMode)
{
    DatabaseManager::instance()->insertReportHistory(
        d.reportId, d.reportTime, triggerMode,
        d.hostname.isEmpty() ? "未知" : d.hostname,
        d.totalHigh, d.totalMedium, d.totalLow, d.totalClean,
        htmlContent, rtfContent);
    // 刷新历史列表（如果已初始化）
    if (m_tblHistory) refreshHistory();
}

// ── 从 DB 恢复定时策略 ────────────────────────────────────────────────────────
void ReportPage::restoreScheduleFromDb()
{
    QVariantMap cfg = DatabaseManager::instance()->queryReportSchedule();
    if (cfg.isEmpty()) return;

    bool enabled = cfg["enabled"].toInt() == 1;
    QString mode = cfg["mode"].toString();
    int hour   = cfg["hour"].toInt();
    int minute = cfg["minute"].toInt();

    // 恢复 UI 状态（先 blockSignals 避免触发 onTimerToggle）
    m_chkTimerEnable->blockSignals(true);
    m_chkTimerEnable->setChecked(enabled);
    m_chkTimerEnable->blockSignals(false);

    QStringList modes = {"每天","每周一","每周五","每小时"};
    int modeIdx = modes.indexOf(mode);
    if (modeIdx < 0) modeIdx = 0;
    m_cmbTimerMode->setCurrentIndex(modeIdx);
    m_spnTimerHour->setValue(hour);
    m_spnTimerMinute->setValue(minute);

    if (enabled) {
        m_cmbTimerMode->setEnabled(true);
        m_spnTimerHour->setEnabled(true);
        m_spnTimerMinute->setEnabled(true);
        // 重新计算下次触发时间
        m_nextFireTime = calcNextFire(mode, hour, minute);
        m_lblNextTime->setText(m_nextFireTime.toString("yyyy-MM-dd HH:mm:ss"));
        m_lblTimerStatus->setText("定时生成已启用（从数据库恢复）");
        qint64 msecs = QDateTime::currentDateTime().msecsTo(m_nextFireTime);
        if (msecs > 0) {
            m_timer->setSingleShot(true);
            m_timer->start(static_cast<int>(qMin(msecs, (qint64)INT_MAX)));
        }
    }
}

// ── 计算下次触发时间 ──────────────────────────────────────────────────────────
QDateTime ReportPage::calcNextFire(const QString &mode, int hour, int minute)
{
    QDateTime now  = QDateTime::currentDateTime();
    QDateTime next = now;
    if (mode == "每小时") {
        next = now.addSecs(3600 - now.time().second() - now.time().minute()*60);
    } else {
        next.setTime(QTime(hour, minute, 0));
        if (next <= now) next = next.addDays(1);
        if (mode == "每周一") { while (next.date().dayOfWeek() != 1) next = next.addDays(1); }
        else if (mode == "每周五") { while (next.date().dayOfWeek() != 5) next = next.addDays(1); }
    }
    return next;
}
