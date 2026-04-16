#include "pages/DynamicScanPage.h"
#include "ui_DynamicScanPage.h"

#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QSplitter>
#include <QScrollArea>
#include <QFrame>
#include <QFileDialog>
#include <QHeaderView>
#include <QLabel>
#include <QTreeWidgetItem>
#include <QDateTime>
#include <QFont>
#include <QMouseEvent>
#include <QSet>

// ─────────────────────────────────────────────────────────────────────────────
// 静态辅助
// ─────────────────────────────────────────────────────────────────────────────
static QString tableStyle() {
    return "QTableWidget{border:1px solid #d0d7e3;font-size:12px;}"
           "QHeaderView::section{background:#e8ecf4;padding:5px 8px;font-weight:600;border:1px solid #d0d7e3;}"
           "QTableWidget::item{padding:5px 8px;}"
           "QTableWidget::item:alternate{background:#fafbfd;}";
}

static void applyTableStyle(QTableWidget *t) {
    if (!t) return;
    t->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    t->horizontalHeader()->setStretchLastSection(true);
    t->verticalHeader()->setVisible(false);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setAlternatingRowColors(true);
    t->setStyleSheet(tableStyle());
}

static void highlightRow(QTableWidget *t, int row, const QString &risk) {
    QColor bg = (risk == "high") ? QColor("#fff1f0") :
                (risk == "medium") ? QColor("#fffbe6") : QColor();
    if (!bg.isValid()) return;
    for (int c = 0; c < t->columnCount(); c++)
        if (t->item(row, c)) t->item(row, c)->setBackground(bg);
}

static QTableWidgetItem* riskItem(const QString &risk) {
    QString text = (risk == "high") ? "高危" :
                   (risk == "medium") ? "中危" :
                   (risk == "low") ? "低危" : "正常";
    auto *item = new QTableWidgetItem(text);
    QFont f = item->font(); f.setBold(true); item->setFont(f);
    if      (risk == "high")   item->setForeground(QColor("#f5222d"));
    else if (risk == "medium") item->setForeground(QColor("#fa8c16"));
    else if (risk == "low")    item->setForeground(QColor("#1890ff"));
    else                       item->setForeground(QColor("#52c41a"));
    return item;
}

static QString btnStyle(const QString &bg) {
    return QString("QPushButton{background:%1;color:#fff;border:none;"
                   "border-radius:3px;padding:5px 14px;font-size:12px;}"
                   "QPushButton:hover{opacity:0.9;}").arg(bg);
}

// ─────────────────────────────────────────────────────────────────────────────
// 构造
// ─────────────────────────────────────────────────────────────────────────────
DynamicScanPage::DynamicScanPage(QWidget *parent)
    : BasePage("动态监测", parent)
{
    ui = new Ui::DynamicScanPage();
    ui->setupUi(this);
    postSetupUi();

    // 绑定外层 Tab
    m_tabMain = ui->m_tabMain;

    // 扫描控制
    m_editPath         = ui->m_editPath;
    m_btnBrowse        = ui->m_btnBrowse;
    m_btnStart         = ui->m_btnStart;
    m_btnStop          = ui->m_btnStop;
    m_lblMonitorStatus = ui->m_lblMonitorStatus;
    m_lblStatus        = ui->m_lblStatus;

    // 内层行为 Tab
    m_tabBehavior = ui->m_tabBehavior;

    // 注册表操作
    m_cmbRegOp    = ui->m_cmbRegOp;
    m_cmbRegRisk  = ui->m_cmbRegRisk;
    m_edtRegKw    = ui->m_edtRegKw;
    m_btnRegQuery = ui->m_btnRegQuery;
    m_tblRegistry = ui->m_tblRegistry;
    applyTableStyle(m_tblRegistry);

    // 文件行为
    m_cmbFileOp    = ui->m_cmbFileOp;
    m_cmbFileRisk  = ui->m_cmbFileRisk;
    m_edtFileKw    = ui->m_edtFileKw;
    m_btnFileQuery = ui->m_btnFileQuery;
    m_tblFile      = ui->m_tblFile;
    applyTableStyle(m_tblFile);

    // 进程行为
    m_cmbProcOp    = ui->m_cmbProcOp;
    m_cmbProcRisk  = ui->m_cmbProcRisk;
    m_edtProcKw    = ui->m_edtProcKw;
    m_btnProcQuery = ui->m_btnProcQuery;
    m_tblProcess   = ui->m_tblProcess;
    applyTableStyle(m_tblProcess);

    // 网络行为
    m_cmbNetProto  = ui->m_cmbNetProto;
    m_cmbNetRisk   = ui->m_cmbNetRisk;
    m_edtNetKw     = ui->m_edtNetKw;
    m_btnNetQuery  = ui->m_btnNetQuery;
    m_tblNetwork   = ui->m_tblNetwork;
    applyTableStyle(m_tblNetwork);

    // SSDT操作
    m_cmbSsdtRisk  = ui->m_cmbSsdtRisk;
    m_edtSsdtKw    = ui->m_edtSsdtKw;
    m_btnSsdtQuery = ui->m_btnSsdtQuery;
    m_tblSsdt      = ui->m_tblSsdt;
    applyTableStyle(m_tblSsdt);

    // 启动项操作
    m_cmbAutorunOp    = ui->m_cmbAutorunOp;
    m_cmbAutorunRisk  = ui->m_cmbAutorunRisk;
    m_edtAutorunKw    = ui->m_edtAutorunKw;
    m_btnAutorunQuery = ui->m_btnAutorunQuery;
    m_tblAutorun      = ui->m_tblAutorun;
    applyTableStyle(m_tblAutorun);

    // 计划任务操作
    m_cmbTaskOp    = ui->m_cmbTaskOp;
    m_cmbTaskRisk  = ui->m_cmbTaskRisk;
    m_edtTaskKw    = ui->m_edtTaskKw;
    m_btnTaskQuery = ui->m_btnTaskQuery;
    m_tblTask      = ui->m_tblTask;
    applyTableStyle(m_tblTask);

    // 浏览器插件操作
    m_cmbPluginOp    = ui->m_cmbPluginOp;
    m_cmbPluginRisk  = ui->m_cmbPluginRisk;
    m_edtPluginKw    = ui->m_edtPluginKw;
    m_btnPluginQuery = ui->m_btnPluginQuery;
    m_tblBrowserPlugin = ui->m_tblBrowserPlugin;
    applyTableStyle(m_tblBrowserPlugin);

    // 文件关联检测
    m_cmbFileAssocStatus = ui->m_cmbFileAssocStatus;
    m_cmbFileAssocRisk   = ui->m_cmbFileAssocRisk;
    m_edtFileAssocKw     = ui->m_edtFileAssocKw;
    m_btnFileAssocQuery  = ui->m_btnFileAssocQuery;
    m_tblFileAssoc       = ui->m_tblFileAssoc;
    applyTableStyle(m_tblFileAssoc);

    // 远控行为分析
    m_cmbRctrlType  = ui->m_cmbRctrlType;
    m_cmbRctrlRisk  = ui->m_cmbRctrlRisk;
    m_edtRctrlKw    = ui->m_edtRctrlKw;
    m_btnRctrlQuery = ui->m_btnRctrlQuery;
    m_tblRctrl      = ui->m_tblRctrl;
    applyTableStyle(m_tblRctrl);

    // 进程链行为分析
    m_scrollCards          = ui->m_scrollCards;
    m_cardContainer        = ui->m_cardContainer;
    m_chainTree            = ui->m_chainTree;
    m_tblProcessDetail     = ui->m_tblProcessDetail;
    applyTableStyle(m_tblProcessDetail);
    m_lblChainBehaviorTitle = ui->m_lblChainBehaviorTitle;
    m_btnRefreshChain       = ui->m_btnRefreshChain;

    // 按钮样式
    m_btnBrowse->setStyleSheet(btnStyle("#595959"));
    m_btnStart->setStyleSheet(btnStyle("#1a3a6a"));
    m_btnStop->setStyleSheet(btnStyle("#8c8c8c"));
    m_btnRefreshChain->setStyleSheet(btnStyle("#1a3a6a"));
    for (auto *b : {m_btnRegQuery, m_btnFileQuery, m_btnProcQuery, m_btnNetQuery,
                    m_btnSsdtQuery, m_btnAutorunQuery, m_btnTaskQuery,
                    m_btnPluginQuery, m_btnFileAssocQuery, m_btnRctrlQuery})
        b->setStyleSheet(btnStyle("#1a3a6a"));

    // 信号连接
    connect(m_btnBrowse,        &QPushButton::clicked, this, &DynamicScanPage::onBrowseFile);
    connect(m_btnStart,         &QPushButton::clicked, this, &DynamicScanPage::onStartScan);
    connect(m_btnStop,          &QPushButton::clicked, this, &DynamicScanPage::onStopScan);
    connect(m_btnRegQuery,      &QPushButton::clicked, this, &DynamicScanPage::onQueryRegistry);
    connect(m_btnFileQuery,     &QPushButton::clicked, this, &DynamicScanPage::onQueryFile);
    connect(m_btnProcQuery,     &QPushButton::clicked, this, &DynamicScanPage::onQueryProcess);
    connect(m_btnNetQuery,      &QPushButton::clicked, this, &DynamicScanPage::onQueryNetwork);
    connect(m_btnSsdtQuery,     &QPushButton::clicked, this, &DynamicScanPage::onQuerySsdt);
    connect(m_btnAutorunQuery,  &QPushButton::clicked, this, &DynamicScanPage::onQueryAutorun);
    connect(m_btnTaskQuery,     &QPushButton::clicked, this, &DynamicScanPage::onQueryTask);
    connect(m_btnPluginQuery,   &QPushButton::clicked, this, &DynamicScanPage::onQueryPlugin);
    connect(m_btnFileAssocQuery,&QPushButton::clicked, this, &DynamicScanPage::onQueryFileAssoc);
    connect(m_btnRctrlQuery,    &QPushButton::clicked, this, &DynamicScanPage::onQueryRctrl);
    connect(m_btnRefreshChain,  &QPushButton::clicked, this, &DynamicScanPage::onRefreshProcessChain);
    connect(m_chainTree, &QTreeWidget::itemClicked,
            this, &DynamicScanPage::onProcessTreeItemClicked);

    // Enter 键触发查询
    connect(m_edtRegKw,      &QLineEdit::returnPressed, this, &DynamicScanPage::onQueryRegistry);
    connect(m_edtFileKw,     &QLineEdit::returnPressed, this, &DynamicScanPage::onQueryFile);
    connect(m_edtProcKw,     &QLineEdit::returnPressed, this, &DynamicScanPage::onQueryProcess);
    connect(m_edtNetKw,      &QLineEdit::returnPressed, this, &DynamicScanPage::onQueryNetwork);
    connect(m_edtSsdtKw,     &QLineEdit::returnPressed, this, &DynamicScanPage::onQuerySsdt);
    connect(m_edtAutorunKw,  &QLineEdit::returnPressed, this, &DynamicScanPage::onQueryAutorun);
    connect(m_edtTaskKw,     &QLineEdit::returnPressed, this, &DynamicScanPage::onQueryTask);
    connect(m_edtPluginKw,   &QLineEdit::returnPressed, this, &DynamicScanPage::onQueryPlugin);
    connect(m_edtFileAssocKw,&QLineEdit::returnPressed, this, &DynamicScanPage::onQueryFileAssoc);
    connect(m_edtRctrlKw,    &QLineEdit::returnPressed, this, &DynamicScanPage::onQueryRctrl);

    refreshData();
}

// ─────────────────────────────────────────────────────────────────────────────
// refreshData
// ─────────────────────────────────────────────────────────────────────────────
void DynamicScanPage::refreshData() {
    onQueryRegistry();
    onQueryFile();
    onQueryProcess();
    onQueryNetwork();
    onQuerySsdt();
    onQueryAutorun();
    onQueryTask();
    onQueryPlugin();
    onQueryFileAssoc();
    onQueryRctrl();
    if (m_tabMain && m_tabMain->currentIndex() == 1)
        loadProcessCards();
    if (m_lblStatus)
        m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 通用查询填充
// ─────────────────────────────────────────────────────────────────────────────
void DynamicScanPage::queryAndFillTable(QTableWidget *tbl,
                                         const QString &type,
                                         const QString &kw,
                                         const QString &risk,
                                         const QString &extraFilter)
{
    if (!tbl) return;
    tbl->setRowCount(0);
    QString sql = "SELECT scan_time,action_type,source_proc,target_path,detail,risk_level "
                  "FROM dynamic_scan WHERE behavior_type=?";
    QVariantList binds;
    binds << type;
    if (!kw.isEmpty()) {
        sql += " AND (action_type LIKE ? OR source_proc LIKE ? OR target_path LIKE ? OR detail LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like << like;
    }
    if (!risk.isEmpty()) {
        sql += " AND risk_level=?";
        binds << risk;
    }
    if (!extraFilter.isEmpty()) sql += " " + extraFilter;
    sql += " ORDER BY id DESC LIMIT 200";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    if (rows.isEmpty()) { loadDemoForTable(tbl, type); return; }
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = tbl->rowCount(); tbl->insertRow(row);
        tbl->setItem(row, 0, new QTableWidgetItem(m["scan_time"].toString().mid(11,8)));
        tbl->setItem(row, 1, new QTableWidgetItem(m["action_type"].toString()));
        if (tbl->columnCount() > 2) {
            auto *pi = new QTableWidgetItem(m["source_proc"].toString());
            pi->setFont(QFont("Consolas",11));
            tbl->setItem(row, 2, pi);
        }
        if (tbl->columnCount() > 3) {
            auto *ti = new QTableWidgetItem(m["target_path"].toString());
            ti->setFont(QFont("Consolas",11));
            tbl->setItem(row, 3, ti);
        }
        if (tbl->columnCount() > 4)
            tbl->setItem(row, 4, new QTableWidgetItem(m["detail"].toString()));
        QString riskVal = m["risk_level"].toString();
        tbl->setItem(row, tbl->columnCount()-1, riskItem(riskVal));
        highlightRow(tbl, row, riskVal);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 各子Tab独立查询 Slots
// ─────────────────────────────────────────────────────────────────────────────
void DynamicScanPage::onQueryRegistry() {
    QString kw = m_edtRegKw ? m_edtRegKw->text().trimmed() : "";
    QStringList riskMap = {"","high","medium","low"};
    int ri = m_cmbRegRisk ? m_cmbRegRisk->currentIndex() : 0;
    QString risk = (ri > 0 && ri < riskMap.size()) ? riskMap[ri] : "";
    QString opFilter;
    if (m_cmbRegOp && m_cmbRegOp->currentIndex() > 0)
        opFilter = " AND action_type='" + m_cmbRegOp->currentText() + "'";
    queryAndFillTable(m_tblRegistry, "registry", kw, risk, opFilter);
}

void DynamicScanPage::onQueryFile() {
    QString kw = m_edtFileKw ? m_edtFileKw->text().trimmed() : "";
    QStringList riskMap = {"","high","medium","low"};
    int ri = m_cmbFileRisk ? m_cmbFileRisk->currentIndex() : 0;
    QString risk = (ri > 0 && ri < riskMap.size()) ? riskMap[ri] : "";
    QString opFilter;
    if (m_cmbFileOp && m_cmbFileOp->currentIndex() > 0)
        opFilter = " AND action_type='" + m_cmbFileOp->currentText() + "'";
    queryAndFillTable(m_tblFile, "file", kw, risk, opFilter);
}

void DynamicScanPage::onQueryProcess() {
    QString kw = m_edtProcKw ? m_edtProcKw->text().trimmed() : "";
    QStringList riskMap = {"","high","medium","low"};
    int ri = m_cmbProcRisk ? m_cmbProcRisk->currentIndex() : 0;
    QString risk = (ri > 0 && ri < riskMap.size()) ? riskMap[ri] : "";
    QString opFilter;
    if (m_cmbProcOp && m_cmbProcOp->currentIndex() > 0)
        opFilter = " AND action_type='" + m_cmbProcOp->currentText() + "'";
    queryAndFillTable(m_tblProcess, "process", kw, risk, opFilter);
}

void DynamicScanPage::onQueryNetwork() {
    QString kw = m_edtNetKw ? m_edtNetKw->text().trimmed() : "";
    QStringList riskMap = {"","high","medium","low"};
    int ri = m_cmbNetRisk ? m_cmbNetRisk->currentIndex() : 0;
    QString risk = (ri > 0 && ri < riskMap.size()) ? riskMap[ri] : "";
    QString protoFilter;
    if (m_cmbNetProto && m_cmbNetProto->currentIndex() > 0)
        protoFilter = " AND action_type='" + m_cmbNetProto->currentText() + "'";
    queryAndFillTable(m_tblNetwork, "network", kw, risk, protoFilter);
}

void DynamicScanPage::onQuerySsdt() {
    QString kw = m_edtSsdtKw ? m_edtSsdtKw->text().trimmed() : "";
    QStringList riskMap = {"","high","medium","low"};
    int ri = m_cmbSsdtRisk ? m_cmbSsdtRisk->currentIndex() : 0;
    QString risk = (ri > 0 && ri < riskMap.size()) ? riskMap[ri] : "";
    queryAndFillTable(m_tblSsdt, "ssdt", kw, risk);
}

void DynamicScanPage::onQueryAutorun() {
    QString kw = m_edtAutorunKw ? m_edtAutorunKw->text().trimmed() : "";
    QStringList riskMap = {"","high","medium","low"};
    int ri = m_cmbAutorunRisk ? m_cmbAutorunRisk->currentIndex() : 0;
    QString risk = (ri > 0 && ri < riskMap.size()) ? riskMap[ri] : "";
    QString opFilter;
    if (m_cmbAutorunOp && m_cmbAutorunOp->currentIndex() > 0)
        opFilter = " AND action_type='" + m_cmbAutorunOp->currentText() + "'";
    queryAndFillTable(m_tblAutorun, "autorun", kw, risk, opFilter);
}

void DynamicScanPage::onQueryTask() {
    QString kw = m_edtTaskKw ? m_edtTaskKw->text().trimmed() : "";
    QStringList riskMap = {"","high","medium","low"};
    int ri = m_cmbTaskRisk ? m_cmbTaskRisk->currentIndex() : 0;
    QString risk = (ri > 0 && ri < riskMap.size()) ? riskMap[ri] : "";
    QString opFilter;
    if (m_cmbTaskOp && m_cmbTaskOp->currentIndex() > 0)
        opFilter = " AND action_type='" + m_cmbTaskOp->currentText() + "'";
    queryAndFillTable(m_tblTask, "task", kw, risk, opFilter);
}

void DynamicScanPage::onQueryPlugin() {
    QString kw = m_edtPluginKw ? m_edtPluginKw->text().trimmed() : "";
    QStringList riskMap = {"","high","medium","low"};
    int ri = m_cmbPluginRisk ? m_cmbPluginRisk->currentIndex() : 0;
    QString risk = (ri > 0 && ri < riskMap.size()) ? riskMap[ri] : "";
    QString opFilter;
    if (m_cmbPluginOp && m_cmbPluginOp->currentIndex() > 0)
        opFilter = " AND action_type='" + m_cmbPluginOp->currentText() + "'";
    queryAndFillTable(m_tblBrowserPlugin, "browser", kw, risk, opFilter);
}

void DynamicScanPage::onQueryFileAssoc() {
    if (!m_tblFileAssoc) return;
    m_tblFileAssoc->setRowCount(0);
    QString kw = m_edtFileAssocKw ? m_edtFileAssocKw->text().trimmed() : "";
    QStringList riskMap = {"","high","medium","low"};
    int ri = m_cmbFileAssocRisk ? m_cmbFileAssocRisk->currentIndex() : 0;
    QString risk = (ri > 0 && ri < riskMap.size()) ? riskMap[ri] : "";
    QString statusFilter;
    if (m_cmbFileAssocStatus && m_cmbFileAssocStatus->currentIndex() > 0)
        statusFilter = m_cmbFileAssocStatus->currentText();

    QString sql = "SELECT extension,default_prog,current_prog,status,risk_level FROM file_assoc WHERE 1=1";
    QVariantList binds;
    if (!kw.isEmpty()) {
        sql += " AND (extension LIKE ? OR default_prog LIKE ? OR current_prog LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like;
    }
    if (!statusFilter.isEmpty()) { sql += " AND status=?"; binds << statusFilter; }
    if (!risk.isEmpty())         { sql += " AND risk_level=?"; binds << risk; }
    sql += " ORDER BY id DESC LIMIT 200";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    if (rows.isEmpty()) { loadDemoForTable(m_tblFileAssoc, "file_assoc"); return; }
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = m_tblFileAssoc->rowCount(); m_tblFileAssoc->insertRow(row);
        m_tblFileAssoc->setItem(row, 0, new QTableWidgetItem(m["extension"].toString()));
        m_tblFileAssoc->setItem(row, 1, new QTableWidgetItem(m["default_prog"].toString()));
        m_tblFileAssoc->setItem(row, 2, new QTableWidgetItem(m["current_prog"].toString()));
        QString st = m["status"].toString();
        auto *si = new QTableWidgetItem(st);
        QFont f = si->font(); f.setBold(true); si->setFont(f);
        if (st == "已篡改")      si->setForeground(QColor("#f5222d"));
        else if (st == "可疑")   si->setForeground(QColor("#fa8c16"));
        else                     si->setForeground(QColor("#52c41a"));
        m_tblFileAssoc->setItem(row, 3, si);
        QString riskVal = m["risk_level"].toString();
        m_tblFileAssoc->setItem(row, 4, riskItem(riskVal));
        highlightRow(m_tblFileAssoc, row, riskVal);
    }
}

void DynamicScanPage::onQueryRctrl() {
    if (!m_tblRctrl) return;
    m_tblRctrl->setRowCount(0);
    QString kw = m_edtRctrlKw ? m_edtRctrlKw->text().trimmed() : "";
    QStringList riskMap = {"","high","medium","low"};
    int ri = m_cmbRctrlRisk ? m_cmbRctrlRisk->currentIndex() : 0;
    QString risk = (ri > 0 && ri < riskMap.size()) ? riskMap[ri] : "";
    QString typeFilter;
    if (m_cmbRctrlType && m_cmbRctrlType->currentIndex() > 0)
        typeFilter = m_cmbRctrlType->currentText();

    QString sql = "SELECT alert_time,behavior_type,proc_name,pid,"
                  "src_ip,src_port,dst_ip,dst_port,protocol,risk_level "
                  "FROM rctrl_behaviors WHERE 1=1";
    QVariantList binds;
    if (!kw.isEmpty()) {
        sql += " AND (proc_name LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR dst_ip LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like << like;
    }
    if (!typeFilter.isEmpty()) { sql += " AND behavior_type=?"; binds << typeFilter; }
    if (!risk.isEmpty())       { sql += " AND risk_level=?";    binds << risk; }
    sql += " ORDER BY id DESC LIMIT 200";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    if (rows.isEmpty()) { loadDemoForTable(m_tblRctrl, "rctrl"); return; }
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = m_tblRctrl->rowCount(); m_tblRctrl->insertRow(row);
        m_tblRctrl->setItem(row, 0, new QTableWidgetItem(m["alert_time"].toString().mid(11,8)));
        // 行为类型（彩色）
        QString bt = m["behavior_type"].toString();
        auto *bti = new QTableWidgetItem(bt);
        QFont f = bti->font(); f.setBold(true); bti->setFont(f);
        if      (bt == "远程下载" || bt == "远程命令执行") bti->setForeground(QColor("#f5222d"));
        else if (bt == "远程监控" || bt == "远程网络配置") bti->setForeground(QColor("#fa8c16"));
        else if (bt == "DNS篡改"  || bt == "路由表篡改")  bti->setForeground(QColor("#722ed1"));
        else                                               bti->setForeground(QColor("#1890ff"));
        m_tblRctrl->setItem(row, 1, bti);
        m_tblRctrl->setItem(row, 2, new QTableWidgetItem(
            m["proc_name"].toString() + "/" + m["pid"].toString()));
        m_tblRctrl->setItem(row, 3, new QTableWidgetItem(m["src_ip"].toString()));
        m_tblRctrl->setItem(row, 4, new QTableWidgetItem(m["src_port"].toString()));
        m_tblRctrl->setItem(row, 5, new QTableWidgetItem(m["dst_ip"].toString()));
        m_tblRctrl->setItem(row, 6, new QTableWidgetItem(m["dst_port"].toString()));
        m_tblRctrl->setItem(row, 7, new QTableWidgetItem(m["protocol"].toString()));
        QString riskVal = m["risk_level"].toString();
        m_tblRctrl->setItem(row, 8, riskItem(riskVal));
        highlightRow(m_tblRctrl, row, riskVal);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 进程链行为分析
// ─────────────────────────────────────────────────────────────────────────────
void DynamicScanPage::loadProcessCards() {
    if (!m_cardContainer) return;
    // 清空旧卡片
    QLayoutItem *child;
    while (m_cardContainer->layout() &&
           (child = m_cardContainer->layout()->takeAt(0)) != nullptr) {
        if (child->widget()) child->widget()->deleteLater();
        delete child;
    }
    if (!m_cardContainer->layout()) {
        auto *lay = new QVBoxLayout(m_cardContainer);
        lay->setContentsMargins(4, 4, 4, 4);
        lay->setSpacing(4);
    }

    auto rows = DatabaseManager::instance()->execSelect(
        "SELECT DISTINCT pid, source_proc, MIN(scan_time) as create_time, "
        "MAX(risk_level) as max_risk FROM dynamic_scan GROUP BY pid, source_proc ORDER BY pid",
        {});

    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int pid = m["pid"].toInt();
        QString name = m["source_proc"].toString();
        QString ct   = m["create_time"].toString().mid(11, 8);
        QString risk = m["max_risk"].toString();
        auto *card = makeProcessCard(pid, name, ct, risk);
        m_cardContainer->layout()->addWidget(card);
    }
    qobject_cast<QVBoxLayout*>(m_cardContainer->layout())->addStretch();
}

QFrame* DynamicScanPage::makeProcessCard(int pid, const QString &name,
                                          const QString &createTime, const QString &risk)
{
    auto *card = new QFrame;
    card->setFrameShape(QFrame::StyledPanel);
    card->setCursor(Qt::PointingHandCursor);
    QString borderColor = (risk == "high") ? "#f5222d" :
                          (risk == "medium") ? "#fa8c16" : "#d0d7e3";
    card->setStyleSheet(QString(
        "QFrame{background:#fff;border:1px solid %1;border-radius:4px;"
        "padding:6px 8px;margin:2px;}"
        "QFrame:hover{background:#e6f7ff;border-color:#1890ff;}").arg(borderColor));

    auto *lay = new QVBoxLayout(card);
    lay->setContentsMargins(4, 4, 4, 4);
    lay->setSpacing(2);

    auto *lblName = new QLabel(name);
    lblName->setStyleSheet("font-size:12px;font-weight:700;color:#1a3a6a;");
    auto *lblPid  = new QLabel(QString("PID: %1  |  %2").arg(pid).arg(createTime));
    lblPid->setStyleSheet("font-size:11px;color:#8c8c8c;");

    lay->addWidget(lblName);
    lay->addWidget(lblPid);

    card->setProperty("pid",  pid);
    card->setProperty("name", name);
    card->installEventFilter(this);
    return card;
}

bool DynamicScanPage::eventFilter(QObject *obj, QEvent *event) {
    if (event->type() == QEvent::MouseButtonPress) {
        auto *card = qobject_cast<QFrame*>(obj);
        if (card) {
            int pid = card->property("pid").toInt();
            QString name = card->property("name").toString();
            m_selectedRootPid = pid;
            buildProcessTree(pid);
            loadBehaviorForPid(pid, name);
            return true;
        }
    }
    return BasePage::eventFilter(obj, event);
}

void DynamicScanPage::buildProcessTree(int rootPid) {
    if (!m_chainTree) return;
    m_chainTree->clear();

    auto rows = DatabaseManager::instance()->execSelect(
        "SELECT DISTINCT pid, source_proc FROM dynamic_scan WHERE pid=? OR pid IN "
        "(SELECT DISTINCT pid FROM dynamic_scan WHERE source_proc IN "
        " (SELECT source_proc FROM dynamic_scan WHERE pid=?)) ORDER BY pid",
        {rootPid, rootPid});

    QMap<int, QTreeWidgetItem*> itemMap;
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int pid = m["pid"].toInt();
        QString name = m["source_proc"].toString();
        if (itemMap.contains(pid)) continue;
        auto *item = (pid == rootPid)
            ? new QTreeWidgetItem(m_chainTree)
            : new QTreeWidgetItem(itemMap.value(rootPid, nullptr));
        item->setText(0, QString("%1 (%2)").arg(name).arg(pid));
        item->setData(0, Qt::UserRole, pid);
        item->setData(0, Qt::UserRole + 1, name);
        if (pid == rootPid) {
            QFont f = item->font(0); f.setBold(true); item->setFont(0, f);
        }
        itemMap[pid] = item;
    }
    m_chainTree->expandAll();
}

void DynamicScanPage::loadBehaviorForPid(int pid, const QString &procName) {
    if (!m_tblProcessDetail) return;
    m_tblProcessDetail->setRowCount(0);
    if (m_lblChainBehaviorTitle)
        m_lblChainBehaviorTitle->setText(
            QString("行为信息 — %1 (PID:%2)").arg(procName).arg(pid));

    auto rows = DatabaseManager::instance()->execSelect(
        "SELECT scan_time,behavior_type,action_type,target_path,detail,risk_level "
        "FROM dynamic_scan WHERE pid=? OR source_proc=? ORDER BY id DESC LIMIT 500",
        {pid, procName});

    static const QMap<QString,QString> btypeMap = {
        {"registry","注册表"},{"file","文件"},{"network","网络"},
        {"ssdt","SSDT/Hook"},{"autorun","自启动"},{"task","计划任务"},
        {"browser","浏览器"},{"process","进程"}
    };

    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = m_tblProcessDetail->rowCount();
        m_tblProcessDetail->insertRow(row);
        m_tblProcessDetail->setItem(row, 0, new QTableWidgetItem(m["scan_time"].toString().mid(11,8)));
        m_tblProcessDetail->setItem(row, 1, new QTableWidgetItem(
            btypeMap.value(m["behavior_type"].toString(), m["behavior_type"].toString())));
        auto *pi = new QTableWidgetItem(m["target_path"].toString());
        pi->setFont(QFont("Consolas", 11));
        m_tblProcessDetail->setItem(row, 2, pi);
        m_tblProcessDetail->setItem(row, 3, new QTableWidgetItem(m["detail"].toString()));
        QString risk = m["risk_level"].toString();
        m_tblProcessDetail->setItem(row, 4, riskItem(risk));
        highlightRow(m_tblProcessDetail, row, risk);
    }

    if (rows.isEmpty()) {
        m_tblProcessDetail->insertRow(0);
        auto *hint = new QTableWidgetItem("暂无该进程的行为记录");
        hint->setForeground(QColor("#8c8c8c"));
        hint->setTextAlignment(Qt::AlignCenter);
        m_tblProcessDetail->setItem(0, 0, hint);
        m_tblProcessDetail->setSpan(0, 0, 1, 5);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 其他 Slots
// ─────────────────────────────────────────────────────────────────────────────
void DynamicScanPage::onRefreshProcessChain() {
    loadProcessCards();
    if (m_chainTree) m_chainTree->clear();
    if (m_tblProcessDetail) m_tblProcessDetail->setRowCount(0);
    if (m_lblChainBehaviorTitle)
        m_lblChainBehaviorTitle->setText("行为信息（请点击左侧进程卡片）");
    m_selectedRootPid = -1;
}

void DynamicScanPage::onProcessTreeItemClicked(QTreeWidgetItem *item, int) {
    if (!item) return;
    int pid = item->data(0, Qt::UserRole).toInt();
    QString name = item->data(0, Qt::UserRole + 1).toString();
    if (name.isEmpty()) name = item->text(0);
    loadBehaviorForPid(pid, name);
}

void DynamicScanPage::onBrowseFile() {
    QString path = QFileDialog::getOpenFileName(this, "选择样本文件", "",
        "可执行文件 (*.exe *.dll *.sys);;所有文件 (*.*)");
    if (!path.isEmpty() && m_editPath) m_editPath->setText(path);
}

void DynamicScanPage::onStartScan() {
    if (!m_editPath) return;
    QString path = m_editPath->text().trimmed();
    if (path.isEmpty()) { if (m_lblStatus) m_lblStatus->setText("请先选择样本文件"); return; }
    if (m_lblMonitorStatus) {
        m_lblMonitorStatus->setText("● 监控中");
        m_lblMonitorStatus->setStyleSheet("font-size:12px;color:#f5222d;font-weight:600;padding:0 8px;");
    }
    if (m_lblStatus) m_lblStatus->setText("正在监控：" + path);
    DatabaseManager::instance()->writeLog(m_role, m_username, "动态监测", "开始监控："+path, "success");
}

void DynamicScanPage::onStopScan() {
    if (m_lblMonitorStatus) {
        m_lblMonitorStatus->setText("● 已停止");
        m_lblMonitorStatus->setStyleSheet("font-size:12px;color:#8c8c8c;font-weight:600;padding:0 8px;");
    }
    if (m_lblStatus) m_lblStatus->setText("监控已停止");
    DatabaseManager::instance()->writeLog(m_role, m_username, "动态监测", "停止监控", "success");
}

// ─────────────────────────────────────────────────────────────────────────────
// 演示数据（数据库为空时填充，与 prototype_v5.html 一致）
// ─────────────────────────────────────────────────────────────────────────────
void DynamicScanPage::loadDemoForTable(QTableWidget *tbl, const QString &type)
{
    if (!tbl) return;
    tbl->setRowCount(0);

    // 通用行填充 lambda
    auto addRow = [&](QStringList cols, const QString &risk) {
        int r = tbl->rowCount(); tbl->insertRow(r);
        for (int c = 0; c < cols.size() && c < tbl->columnCount() - 1; c++)
            tbl->setItem(r, c, new QTableWidgetItem(cols[c]));
        tbl->setItem(r, tbl->columnCount()-1, riskItem(risk));
        highlightRow(tbl, r, risk);
    };

    if (type == "registry") {
        addRow({"08:12:33","写入","svchost32.exe","HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","添加自启动项 svchost32.exe"}, "high");
        addRow({"08:13:01","写入","svchost32.exe","HKLM\\SYSTEM\\CurrentControlSet\\Services\\malware_svc","创建恶意服务"}, "high");
        addRow({"08:14:22","读取","explorer.exe","HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer","读取 Explorer 配置"}, "low");
        addRow({"08:15:10","删除","svchost32.exe","HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions","删除 Defender 排除项"}, "medium");
    } else if (type == "file") {
        addRow({"08:12:45","创建","svchost32.exe","C:\\Windows\\Temp\\payload.exe","释放恶意载荷"}, "high");
        addRow({"08:13:20","修改","svchost32.exe","C:\\Windows\\System32\\drivers\\etc\\hosts","篡改 hosts 文件"}, "high");
        addRow({"08:14:05","读取","chrome.exe","C:\\Users\\user01\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data","读取 Chrome 密码数据库"}, "medium");
        addRow({"08:15:30","创建","svchost32.exe","C:\\Windows\\Temp\\inject.dll","释放注入模块"}, "high");
        addRow({"08:16:00","读取","notepad.exe","C:\\Users\\user01\\Documents\\report.docx","正常文件读取"}, "low");
    } else if (type == "process") {
        addRow({"08:12:50","注入","svchost32.exe","explorer.exe","DLL 注入 explorer.exe"}, "high");
        addRow({"08:13:35","创建","svchost32.exe","C:\\Windows\\Temp\\payload.exe","创建子进程执行载荷"}, "high");
        addRow({"08:14:15","终止","svchost32.exe","MsMpEng.exe","终止 Windows Defender 进程"}, "high");
    } else if (type == "network") {
        addRow({"08:13:05","TCP 连接","svchost32.exe","185.220.101.45:4444","连接 C2 服务器"}, "high");
        addRow({"08:13:40","DNS 查询","svchost32.exe","malware-c2.example.com","解析 C2 域名"}, "high");
        addRow({"08:14:30","HTTP POST","svchost32.exe","http://185.220.101.45/upload","上传窃取数据"}, "high");
        addRow({"08:15:00","TCP 连接","chrome.exe","142.250.80.46:443","Chrome 正常 HTTPS 连接"}, "low");
    } else if (type == "ssdt") {
        addRow({"08:12:40","Hook","svchost32.exe","NtQuerySystemInformation","SSDT Hook 系统查询函数"}, "high");
        addRow({"08:12:41","Hook","svchost32.exe","NtOpenProcess","SSDT Hook 进程打开函数"}, "high");
        addRow({"08:12:42","Hook","svchost32.exe","NtCreateFile","SSDT Hook 文件创建函数"}, "medium");
    } else if (type == "autorun") {
        addRow({"08:12:33","新增","svchost32.exe","HKCU\\Run\\svchost32","添加注册表自启动"}, "high");
        addRow({"08:13:00","新增","svchost32.exe","C:\\Users\\user01\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\malware.lnk","添加启动文件夹快捷方式"}, "high");
    } else if (type == "task") {
        addRow({"08:13:10","创建","svchost32.exe","MalwareTask","创建计划任务每小时执行 payload.exe"}, "high");
        addRow({"08:14:00","修改","svchost32.exe","WindowsUpdate","篡改系统更新计划任务"}, "medium");
    } else if (type == "browser") {
        addRow({"08:14:20","安装","svchost32.exe","C:\\Windows\\Temp\\chrome_ext\\keylogger","安装恶意 Chrome 扩展"}, "high");
        addRow({"08:14:50","读取","chrome.exe","C:\\Users\\user01\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies","读取 Cookie 数据"}, "medium");
    }
}
