#include "pages/DynamicScanPage.h"
#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QSplitter>
#include <QFileDialog>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QHeaderView>
#include <QGroupBox>
#include <QLabel>
#include <QTreeWidgetItem>
#include <QDateTime>
#include <QFont>

static QString tableStyle() {
    return "QTableWidget{border:1px solid #d0d7e3;font-size:12px;}"
           "QHeaderView::section{background:#e8ecf4;padding:5px 8px;font-weight:600;border:1px solid #d0d7e3;}"
           "QTableWidget::item{padding:5px 8px;}"
           "QTableWidget::item:alternate{background:#fafbfd;}";
}

static QTableWidget* makeTab(const QStringList &headers) {
    QTableWidget *t = new QTableWidget(0, headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    t->horizontalHeader()->setStretchLastSection(true);
    t->verticalHeader()->setVisible(false);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setAlternatingRowColors(true);
    t->setStyleSheet(tableStyle());
    return t;
}

static void highlightRow(QTableWidget *t, int row, const QString &risk) {
    QColor bg = (risk == "high") ? QColor("#fff1f0") :
                (risk == "medium") ? QColor("#fffbe6") : QColor();
    if (!bg.isValid()) return;
    for (int c = 0; c < t->columnCount(); c++)
        if (t->item(row, c)) t->item(row, c)->setBackground(bg);
}

static QTableWidgetItem* riskItem(const QString &risk) {
    QString text = (risk == "high") ? "高危" : (risk == "medium") ? "注意" : "正常";
    QTableWidgetItem *item = new QTableWidgetItem(text);
    QFont f = item->font(); f.setBold(true); item->setFont(f);
    if (risk == "high") item->setForeground(QColor("#f5222d"));
    else if (risk == "medium") item->setForeground(QColor("#fa8c16"));
    else item->setForeground(QColor("#52c41a"));
    return item;
}

DynamicScanPage::DynamicScanPage(QWidget *parent)
    : BasePage("动态行为检测", parent)
{
    setupUi();
    refreshData();
}

void DynamicScanPage::setupUi()
{
    // 控制栏
    QHBoxLayout *ctrlRow = new QHBoxLayout;
    ctrlRow->setContentsMargins(0,0,0,8);
    m_editPath = new QLineEdit;
    m_editPath->setPlaceholderText("输入目标文件路径或拖拽文件...");
    // 不设置默认路径，由用户手动选择或外部入库后刷新
    m_editPath->setStyleSheet("QLineEdit{font-size:12px;padding:5px 8px;border:1px solid #d0d7e3;border-radius:3px;}");

    auto makeBtn = [](const QString &text, const QString &bg) -> QPushButton* {
        QPushButton *b = new QPushButton(text);
        b->setFixedWidth(90);
        b->setStyleSheet(QString("QPushButton{background:%1;color:#fff;border:none;border-radius:3px;"
                                 "padding:5px 10px;font-size:12px;}"
                                 "QPushButton:hover{opacity:0.9;}").arg(bg));
        return b;
    };
    m_btnBrowse = makeBtn("浏览", "#595959");
    m_btnBrowse->setFixedWidth(70);
    m_btnStart  = makeBtn("开始监控", "#1a3a6a");
    m_btnStop   = makeBtn("停止", "#8c8c8c");

    m_lblMonitorStatus = new QLabel("● 就绪");
    m_lblMonitorStatus->setStyleSheet("font-size:12px;color:#52c41a;font-weight:600;padding:0 8px;");

    connect(m_btnBrowse, &QPushButton::clicked, this, &DynamicScanPage::onBrowseFile);
    connect(m_btnStart,  &QPushButton::clicked, this, &DynamicScanPage::onStartScan);
    connect(m_btnStop,   &QPushButton::clicked, this, &DynamicScanPage::onStopScan);

    ctrlRow->addWidget(m_editPath, 1);
    ctrlRow->addWidget(m_btnBrowse);
    ctrlRow->addWidget(m_btnStart);
    ctrlRow->addWidget(m_btnStop);
    ctrlRow->addWidget(m_lblMonitorStatus);
    m_mainLayout->addLayout(ctrlRow);

    // Tab 控件
    m_tabBehavior = new QTabWidget;
    m_tabBehavior->setStyleSheet(
        "QTabWidget::pane{border:1px solid #d0d7e3;}"
        "QTabBar::tab{padding:6px 14px;font-size:12px;background:#f0f3fa;border:1px solid #d0d7e3;}"
        "QTabBar::tab:selected{background:#fff;color:#1a3a6a;font-weight:600;border-bottom:2px solid #1a3a6a;}");

    // Tab1: 注册表操作
    m_tblRegistry = makeTab({"时间", "操作", "注册表路径", "值", "风险"});
    m_tabBehavior->addTab(m_tblRegistry, "注册表操作");

    // Tab2: 文件行为
    m_tblFile = makeTab({"时间", "操作", "文件路径", "风险"});
    m_tabBehavior->addTab(m_tblFile, "文件行为");

    // Tab3: 进程行为（进程树 + 操作记录）
    QWidget *procWidget = new QWidget;
    QVBoxLayout *procLay = new QVBoxLayout(procWidget);
    procLay->setContentsMargins(4,8,4,4);
    procLay->setSpacing(6);

    QLabel *treeLbl = new QLabel("进程树");
    treeLbl->setStyleSheet("font-size:12px;font-weight:600;color:#1a3a6a;");
    procLay->addWidget(treeLbl);

    m_treeProcess = new QTreeWidget;
    m_treeProcess->setHeaderLabels({"进程名", "PID", "说明", "风险"});
    m_treeProcess->setColumnWidth(0, 280);
    m_treeProcess->setColumnWidth(1, 70);
    m_treeProcess->setColumnWidth(2, 200);
    m_treeProcess->setFixedHeight(160);
    m_treeProcess->setAlternatingRowColors(true);
    m_treeProcess->setStyleSheet(
        "QTreeWidget{border:1px solid #d0d7e3;font-size:12px;}"
        "QHeaderView::section{background:#e8ecf4;padding:5px 8px;font-weight:600;border:1px solid #d0d7e3;}"
        "QTreeWidget::item{padding:4px 6px;}"
        "QTreeWidget::item:alternate{background:#fafbfd;}");
    procLay->addWidget(m_treeProcess);

    QLabel *detailLbl = new QLabel("进程操作记录");
    detailLbl->setStyleSheet("font-size:12px;font-weight:600;color:#1a3a6a;margin-top:4px;");
    procLay->addWidget(detailLbl);

    m_tblProcessDetail = makeTab({"时间", "操作", "目标进程", "PID", "风险"});
    procLay->addWidget(m_tblProcessDetail, 1);
    m_tabBehavior->addTab(procWidget, "进程行为");

    // Tab4: 网络行为
    m_tblNetwork = makeTab({"时间", "协议", "本地地址", "远程地址", "数据量", "风险"});
    m_tabBehavior->addTab(m_tblNetwork, "网络行为");

    // Tab5: SSDT操作
    m_tblSsdt = makeTab({"时间", "SSDT序号", "原始函数", "钩子地址", "钩子模块", "风险"});
    m_tabBehavior->addTab(m_tblSsdt, "SSDT操作");

    // Tab6: 启动项操作
    m_tblAutorun = makeTab({"时间", "操作", "启动项名称", "路径/值", "风险"});
    m_tabBehavior->addTab(m_tblAutorun, "启动项操作");

    // Tab7: 计划任务操作
    m_tblTask = makeTab({"时间", "操作", "任务名称", "触发条件", "执行程序", "风险"});
    m_tabBehavior->addTab(m_tblTask, "计划任务操作");

    // Tab8: 浏览器插件操作
    m_tblBrowserPlugin = makeTab({"时间", "操作", "浏览器", "插件名称", "路径", "风险"});
    m_tabBehavior->addTab(m_tblBrowserPlugin, "浏览器插件操作");

    m_mainLayout->addWidget(m_tabBehavior, 1);
}

void DynamicScanPage::refreshData()
{
    loadBehaviorData("all");
}

void DynamicScanPage::loadBehaviorData(const QString &/*type*/)
{
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    bool hasData = false;

    // 通用填表 lambda（从 dynamic_scan 表）
    auto fillTable = [&](QTableWidget *tbl, const QString &behaviorType) {
        tbl->setRowCount(0);
        if (!db.isOpen()) return;
        QSqlQuery q(db);
        q.prepare("SELECT scan_time,action_type,source_proc,target_path,detail,risk_level "
                  "FROM dynamic_scan WHERE behavior_type=? ORDER BY id DESC LIMIT 100");
        q.addBindValue(behaviorType);
        if (!q.exec()) return;
        while (q.next()) {
            hasData = true;
            int row = tbl->rowCount(); tbl->insertRow(row);
            tbl->setItem(row, 0, new QTableWidgetItem(q.value(0).toString().mid(11,8)));
            tbl->setItem(row, 1, new QTableWidgetItem(q.value(1).toString()));
            if (tbl->columnCount() > 2) {
                QTableWidgetItem *pi = new QTableWidgetItem(q.value(2).toString());
                pi->setFont(QFont("Consolas", 11));
                tbl->setItem(row, 2, pi);
            }
            if (tbl->columnCount() > 3) {
                QTableWidgetItem *ti = new QTableWidgetItem(q.value(3).toString());
                ti->setFont(QFont("Consolas", 11));
                tbl->setItem(row, 3, ti);
            }
            if (tbl->columnCount() > 4) tbl->setItem(row, 4, new QTableWidgetItem(q.value(4).toString()));
            QString risk = q.value(5).toString();
            tbl->setItem(row, tbl->columnCount()-1, riskItem(risk));
            highlightRow(tbl, row, risk);
        }
    };

    fillTable(m_tblRegistry, "registry");
    fillTable(m_tblFile,     "file");
    fillTable(m_tblNetwork,  "network");
    fillTable(m_tblSsdt,     "ssdt");
    fillTable(m_tblAutorun,  "autorun");
    fillTable(m_tblTask,     "task");
    fillTable(m_tblBrowserPlugin, "browser");

    // 进程行为：树形 + 详情
    m_treeProcess->clear();
    m_tblProcessDetail->setRowCount(0);
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.prepare("SELECT scan_time,action_type,source_proc,target_path,detail,risk_level "
                  "FROM dynamic_scan WHERE behavior_type='process' ORDER BY id ASC LIMIT 50");
        q.exec();
        QTreeWidgetItem *root = nullptr;
        while (q.next()) {
            hasData = true;
            if (!root) {
                root = new QTreeWidgetItem(m_treeProcess);
                root->setText(0, q.value(2).toString());
                root->setText(1, "--");
                root->setText(2, "目标样本");
                root->setForeground(0, QColor("#f5222d"));
                root->setText(3, "高危");
                m_treeProcess->addTopLevelItem(root);
            }
            QTreeWidgetItem *child = new QTreeWidgetItem(root);
            child->setText(0, q.value(3).toString());
            child->setText(1, "--");
            child->setText(2, q.value(1).toString());
            QString risk = q.value(5).toString();
            child->setForeground(0, risk=="high"?QColor("#f5222d"):QColor("#fa8c16"));
            child->setText(3, risk=="high"?"高危":"注意");

            int row = m_tblProcessDetail->rowCount(); m_tblProcessDetail->insertRow(row);
            m_tblProcessDetail->setItem(row,0,new QTableWidgetItem(q.value(0).toString().mid(11,8)));
            m_tblProcessDetail->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
            QTableWidgetItem *tpi = new QTableWidgetItem(q.value(3).toString());
            tpi->setFont(QFont("Consolas",11));
            m_tblProcessDetail->setItem(row,2,tpi);
            m_tblProcessDetail->setItem(row,3,new QTableWidgetItem("--"));
            m_tblProcessDetail->setItem(row,4,riskItem(risk));
            highlightRow(m_tblProcessDetail, row, risk);
        }
        if (root) m_treeProcess->expandAll();
    }

    Q_UNUSED(hasData);

    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void DynamicScanPage::onBrowseFile()
{
    QString path = QFileDialog::getOpenFileName(this, "选择样本文件", "",
        "可执行文件 (*.exe *.dll *.sys);;所有文件 (*.*)");
    if (!path.isEmpty()) m_editPath->setText(path);
}

void DynamicScanPage::onStartScan()
{
    QString path = m_editPath->text().trimmed();
    if (path.isEmpty()) { m_lblStatus->setText("请先选择样本文件"); return; }
    m_lblMonitorStatus->setText("● 监控中");
    m_lblMonitorStatus->setStyleSheet("font-size:12px;color:#f5222d;font-weight:600;padding:0 8px;");
    m_lblStatus->setText("正在监控：" + path);
    DatabaseManager::instance()->writeLog(m_role, m_username, "动态行为检测", "开始监控："+path, "success");
}

void DynamicScanPage::onStopScan()
{
    m_lblMonitorStatus->setText("● 已停止");
    m_lblMonitorStatus->setStyleSheet("font-size:12px;color:#8c8c8c;font-weight:600;padding:0 8px;");
    m_lblStatus->setText("监控已停止");
    DatabaseManager::instance()->writeLog(m_role, m_username, "动态行为检测", "停止监控", "success");
}
