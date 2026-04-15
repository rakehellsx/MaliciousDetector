#include "pages/DynamicScanPage.h"
#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QSplitter>
#include <QScrollArea>
#include <QFrame>
#include <QGroupBox>
#include <QFileDialog>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QHeaderView>
#include <QLabel>
#include <QTreeWidgetItem>
#include <QDateTime>
#include <QFont>
#include <QMouseEvent>
#include <QStyle>
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

static QTableWidget* makeTab(const QStringList &headers) {
    auto *t = new QTableWidget(0, headers.size());
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

// ─────────────────────────────────────────────────────────────────────────────
// 构造
// ─────────────────────────────────────────────────────────────────────────────
DynamicScanPage::DynamicScanPage(QWidget *parent)
    : BasePage("动态行为检测", parent)
{
    setupUi();
    refreshData();
}

void DynamicScanPage::setupUi() {
    // 外层双 Tab
    m_tabOuter = new QTabWidget;
    m_tabOuter->setStyleSheet(
        "QTabWidget::pane{border:1px solid #d0d7e3;background:#fff;}"
        "QTabBar::tab{padding:8px 22px;font-size:13px;font-weight:600;"
        "  background:#f0f3fa;border:1px solid #d0d7e3;}"
        "QTabBar::tab:selected{background:#fff;color:#1a3a6a;"
        "  border-bottom:2px solid #1a3a6a;}");

    m_tabOuter->addTab(buildGlobalTab(), "全局行为监测");
    m_tabOuter->addTab(buildChainTab(),  "进程链行为分析");

    m_mainLayout->addWidget(m_tabOuter, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 1：全局行为监测
// ─────────────────────────────────────────────────────────────────────────────
QWidget* DynamicScanPage::buildGlobalTab() {
    auto *page   = new QWidget;
    auto *vbox   = new QVBoxLayout(page);
    vbox->setContentsMargins(8, 8, 8, 8);
    vbox->setSpacing(6);

    // 控制栏
    auto *ctrlRow = new QHBoxLayout;
    ctrlRow->setSpacing(6);
    m_editPath = new QLineEdit;
    m_editPath->setPlaceholderText("输入目标文件路径或拖拽文件...");
    m_editPath->setStyleSheet("QLineEdit{font-size:12px;padding:5px 8px;"
                               "border:1px solid #d0d7e3;border-radius:3px;}");

    auto makeBtn = [](const QString &text, const QString &bg) -> QPushButton* {
        auto *b = new QPushButton(text);
        b->setFixedWidth(90);
        b->setStyleSheet(QString("QPushButton{background:%1;color:#fff;border:none;"
                                 "border-radius:3px;padding:5px 10px;font-size:12px;}"
                                 "QPushButton:hover{opacity:0.9;}").arg(bg));
        return b;
    };
    m_btnBrowse = makeBtn("浏览", "#595959");
    m_btnBrowse->setFixedWidth(70);
    m_btnStart  = makeBtn("开始监控", "#1a3a6a");
    m_btnStop   = makeBtn("停止",     "#8c8c8c");

    m_lblMonitorStatus = new QLabel("● 就绪");
    m_lblMonitorStatus->setStyleSheet("font-size:12px;color:#52c41a;font-weight:600;padding:0 8px;");

    ctrlRow->addWidget(m_editPath, 1);
    ctrlRow->addWidget(m_btnBrowse);
    ctrlRow->addWidget(m_btnStart);
    ctrlRow->addWidget(m_btnStop);
    ctrlRow->addWidget(m_lblMonitorStatus);
    vbox->addLayout(ctrlRow);

    // 查询栏
    auto *qRow = new QHBoxLayout;
    qRow->setSpacing(6);
    m_edtBehaviorKw = new QLineEdit;
    m_edtBehaviorKw->setPlaceholderText("操作类型 / 路径 / 进程名");
    m_edtBehaviorKw->setClearButtonEnabled(true);
    m_edtBehaviorKw->setFixedWidth(220);
    m_cmbBehaviorRisk = new QComboBox;
    m_cmbBehaviorRisk->addItems({"全部风险", "高危(high)", "中危(medium)", "低危(low)"});
    auto *btnQ = new QPushButton("查询");
    btnQ->setObjectName("btnPrimary");
    btnQ->setFixedWidth(70);
    auto *btnR = new QPushButton("刷新");
    btnR->setObjectName("btnSecondary");
    btnR->setFixedWidth(70);
    m_lblStatus = new QLabel;
    m_lblStatus->setStyleSheet("color:#8c8c8c;font-size:11px;");

    qRow->addWidget(new QLabel("行为关键字："));
    qRow->addWidget(m_edtBehaviorKw);
    qRow->addSpacing(8);
    qRow->addWidget(new QLabel("风险："));
    qRow->addWidget(m_cmbBehaviorRisk);
    qRow->addWidget(btnQ);
    qRow->addWidget(btnR);
    qRow->addWidget(m_lblStatus, 1);
    vbox->addLayout(qRow);

    // 行为 Tab
    m_tabBehavior = new QTabWidget;
    m_tabBehavior->setStyleSheet(
        "QTabWidget::pane{border:1px solid #d0d7e3;}"
        "QTabBar::tab{padding:6px 14px;font-size:12px;background:#f0f3fa;"
        "  border:1px solid #d0d7e3;}"
        "QTabBar::tab:selected{background:#fff;color:#1a3a6a;"
        "  font-weight:600;border-bottom:2px solid #1a3a6a;}");

    m_tblRegistry     = makeTab({"时间","操作","进程","注册表路径","详情","风险"});
    m_tblFile         = makeTab({"时间","操作","进程","文件路径","详情","风险"});
    m_tblNetwork      = makeTab({"时间","协议","进程","本地地址","远程地址","详情","风险"});
    m_tblSsdt         = makeTab({"时间","SSDT序号","进程","原始函数","钩子地址","风险"});
    m_tblAutorun      = makeTab({"时间","操作","进程","启动项名称","路径/值","风险"});
    m_tblTask         = makeTab({"时间","操作","进程","任务名称","执行程序","风险"});
    m_tblBrowserPlugin= makeTab({"时间","操作","浏览器","插件名称","路径","风险"});
    m_tblProcessDetail= makeTab({"时间","操作","源进程","目标进程","详情","风险"});

    m_tabBehavior->addTab(m_tblRegistry,      "注册表操作");
    m_tabBehavior->addTab(m_tblFile,          "文件行为");
    m_tabBehavior->addTab(m_tblNetwork,       "网络行为");
    m_tabBehavior->addTab(m_tblSsdt,          "SSDT操作");
    m_tabBehavior->addTab(m_tblAutorun,       "启动项操作");
    m_tabBehavior->addTab(m_tblTask,          "计划任务操作");
    m_tabBehavior->addTab(m_tblBrowserPlugin, "浏览器插件操作");
    m_tabBehavior->addTab(m_tblProcessDetail, "进程行为");

    vbox->addWidget(m_tabBehavior, 1);

    // 信号
    connect(m_btnBrowse, &QPushButton::clicked, this, &DynamicScanPage::onBrowseFile);
    connect(m_btnStart,  &QPushButton::clicked, this, &DynamicScanPage::onStartScan);
    connect(m_btnStop,   &QPushButton::clicked, this, &DynamicScanPage::onStopScan);
    connect(btnQ,        &QPushButton::clicked, this, &DynamicScanPage::onQueryBehavior);
    connect(btnR,        &QPushButton::clicked, this, &DynamicScanPage::refreshData);
    connect(m_edtBehaviorKw, &QLineEdit::returnPressed, this, &DynamicScanPage::onQueryBehavior);
    connect(m_cmbBehaviorRisk, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &DynamicScanPage::onQueryBehavior);

    return page;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 2：进程链行为分析（左 | 中 | 右）
// ─────────────────────────────────────────────────────────────────────────────
QWidget* DynamicScanPage::buildChainTab() {
    auto *page = new QWidget;
    auto *vbox = new QVBoxLayout(page);
    vbox->setContentsMargins(8, 8, 8, 8);
    vbox->setSpacing(6);

    // 顶部工具栏
    auto *toolbar = new QHBoxLayout;
    auto *lblTitle = new QLabel("进程链行为分析");
    lblTitle->setStyleSheet("font-size:14px;font-weight:700;color:#1a3a6a;");
    toolbar->addWidget(lblTitle);
    toolbar->addStretch();
    m_btnRefreshChain = new QPushButton("刷新进程列表");
    m_btnRefreshChain->setStyleSheet(
        "QPushButton{background:#1a3a6a;color:#fff;border-radius:3px;padding:5px 16px;}"
        "QPushButton:hover{background:#2a5a9a;}");
    toolbar->addWidget(m_btnRefreshChain);
    vbox->addLayout(toolbar);

    // 三栏分割器
    auto *splitter = new QSplitter(Qt::Horizontal);
    splitter->setHandleWidth(4);
    splitter->setStyleSheet("QSplitter::handle{background:#e0e6f0;}");

    // ── 左栏：进程卡片 ────────────────────────────────────────────────────────
    auto *leftPanel = new QWidget;
    leftPanel->setMinimumWidth(190);
    leftPanel->setMaximumWidth(270);
    auto *leftVbox = new QVBoxLayout(leftPanel);
    leftVbox->setContentsMargins(0, 0, 4, 0);
    leftVbox->setSpacing(0);

    auto *leftHeader = new QLabel("  进程列表");
    leftHeader->setStyleSheet(
        "font-size:13px;font-weight:700;color:#fff;"
        "background:#1a3a6a;padding:7px 6px;");
    leftVbox->addWidget(leftHeader);

    m_scrollCards = new QScrollArea;
    m_scrollCards->setWidgetResizable(true);
    m_scrollCards->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_scrollCards->setStyleSheet(
        "QScrollArea{border:1px solid #d0d7e3;background:#f5f7fa;}");

    m_cardContainer = new QWidget;
    auto *cardLayout = new QVBoxLayout(m_cardContainer);
    cardLayout->setSpacing(6);
    cardLayout->setContentsMargins(6, 6, 6, 6);
    cardLayout->addStretch();

    m_scrollCards->setWidget(m_cardContainer);
    leftVbox->addWidget(m_scrollCards, 1);
    splitter->addWidget(leftPanel);

    // ── 中栏：进程树 ──────────────────────────────────────────────────────────
    auto *midPanel = new QWidget;
    midPanel->setMinimumWidth(240);
    auto *midVbox = new QVBoxLayout(midPanel);
    midVbox->setContentsMargins(4, 0, 4, 0);
    midVbox->setSpacing(0);

    auto *midHeader = new QLabel("  子进程树");
    midHeader->setStyleSheet(
        "font-size:13px;font-weight:700;color:#fff;"
        "background:#722ed1;padding:7px 6px;");
    midVbox->addWidget(midHeader);

    m_chainTree = new QTreeWidget;
    m_chainTree->setHeaderLabels({"进程名称", "PID", "风险"});
    m_chainTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_chainTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_chainTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_chainTree->setStyleSheet(
        "QTreeWidget{font-size:12px;border:1px solid #d0d7e3;background:#fff;}"
        "QTreeWidget::item{padding:4px 2px;}"
        "QTreeWidget::item:selected{background:#e6f7ff;color:#1890ff;}"
        "QHeaderView::section{background:#e8ecf4;font-weight:600;padding:4px;}");
    m_chainTree->setAlternatingRowColors(true);
    midVbox->addWidget(m_chainTree, 1);
    splitter->addWidget(midPanel);

    // ── 右栏：行为信息 ────────────────────────────────────────────────────────
    auto *rightPanel = new QWidget;
    rightPanel->setMinimumWidth(280);
    auto *rightVbox = new QVBoxLayout(rightPanel);
    rightVbox->setContentsMargins(4, 0, 0, 0);
    rightVbox->setSpacing(0);

    m_lblChainBehaviorTitle = new QLabel("  行为信息（请点击左侧进程树中的进程）");
    m_lblChainBehaviorTitle->setStyleSheet(
        "font-size:13px;font-weight:700;color:#fff;"
        "background:#fa8c16;padding:7px 6px;");
    rightVbox->addWidget(m_lblChainBehaviorTitle);

    m_chainBehavior = makeTab({"时间","行为类型","操作","目标路径/地址","详情","风险"});
    rightVbox->addWidget(m_chainBehavior, 1);
    splitter->addWidget(rightPanel);

    // 初始宽度比 2:3:5
    splitter->setSizes({220, 280, 500});

    vbox->addWidget(splitter, 1);

    // 信号
    connect(m_btnRefreshChain, &QPushButton::clicked,
            this, &DynamicScanPage::onRefreshProcessChain);
    connect(m_chainTree, &QTreeWidget::itemClicked,
            this, &DynamicScanPage::onProcessTreeItemClicked);

    return page;
}

// ─────────────────────────────────────────────────────────────────────────────
// 进程卡片
// ─────────────────────────────────────────────────────────────────────────────
QFrame* DynamicScanPage::makeProcessCard(int pid, const QString &name,
                                          const QString &createTime, const QString &risk) {
    auto *card = new QFrame;
    card->setObjectName(QString("card_%1").arg(pid));
    card->setCursor(Qt::PointingHandCursor);
    card->setProperty("pid", pid);
    card->setProperty("procName", name);

    QString borderColor = "#d0d7e3", bgColor = "#fff", riskText = "正常", riskColor = "#52c41a";
    if      (risk == "high")   { borderColor="#ff4d4f"; bgColor="#fff1f0"; riskText="高危"; riskColor="#f5222d"; }
    else if (risk == "medium") { borderColor="#faad14"; bgColor="#fffbe6"; riskText="中危"; riskColor="#fa8c16"; }
    else if (risk == "low")    { borderColor="#1890ff"; bgColor="#e6f7ff"; riskText="低危"; riskColor="#1890ff"; }

    card->setStyleSheet(QString(
        "QFrame#card_%1{border:1px solid %2;border-radius:6px;background:%3;padding:2px;}"
        "QFrame#card_%1:hover{border:2px solid #1890ff;background:#e6f7ff;}")
        .arg(pid).arg(borderColor).arg(bgColor));

    auto *lay = new QVBoxLayout(card);
    lay->setContentsMargins(10, 8, 10, 8);
    lay->setSpacing(3);

    auto *topRow = new QHBoxLayout;
    auto *lblName = new QLabel(name);
    lblName->setStyleSheet("font-size:13px;font-weight:700;color:#262626;");
    topRow->addWidget(lblName, 1);

    auto *lblRisk = new QLabel(riskText);
    lblRisk->setStyleSheet(QString(
        "font-size:11px;font-weight:600;color:#fff;"
        "background:%1;border-radius:3px;padding:1px 6px;").arg(riskColor));
    topRow->addWidget(lblRisk);
    lay->addLayout(topRow);

    auto *lblPid = new QLabel(QString("PID: %1").arg(pid));
    lblPid->setStyleSheet("font-size:11px;color:#8c8c8c;");
    lay->addWidget(lblPid);

    if (!createTime.isEmpty()) {
        auto *lblTime = new QLabel(createTime.left(19));
        lblTime->setStyleSheet("font-size:11px;color:#8c8c8c;");
        lay->addWidget(lblTime);
    }

    card->installEventFilter(this);
    return card;
}

// ─────────────────────────────────────────────────────────────────────────────
// 事件过滤（卡片点击）
// ─────────────────────────────────────────────────────────────────────────────
bool DynamicScanPage::eventFilter(QObject *obj, QEvent *event) {
    if (event->type() == QEvent::MouseButtonPress) {
        auto *frame = qobject_cast<QFrame*>(obj);
        if (frame && frame->property("pid").isValid()) {
            int pid = frame->property("pid").toInt();
            QString name = frame->property("procName").toString();
            m_selectedRootPid = pid;
            buildProcessTree(pid);
            m_chainBehavior->setRowCount(0);
            m_lblChainBehaviorTitle->setText(
                QString("  行为信息 — %1 (PID:%2) 及其子进程（点击进程树查看）")
                .arg(name).arg(pid));
        }
    }
    return BasePage::eventFilter(obj, event);
}

// ─────────────────────────────────────────────────────────────────────────────
// 加载进程卡片
// ─────────────────────────────────────────────────────────────────────────────
void DynamicScanPage::loadProcessCards() {
    // 清空旧卡片
    auto *lay = static_cast<QVBoxLayout*>(m_cardContainer->layout());
    QLayoutItem *child;
    while ((child = lay->takeAt(0)) != nullptr) {
        if (child->widget()) child->widget()->deleteLater();
        delete child;
    }

    QString sql =
        "SELECT pid, name, collected_at, risk FROM process_info "
        "ORDER BY CASE risk WHEN 'high' THEN 0 WHEN 'medium' THEN 1 "
        "WHEN 'low' THEN 2 ELSE 3 END, name LIMIT 60";
    auto rows = DatabaseManager::instance()->execSelect(sql, {});

    if (rows.isEmpty()) {
        auto *hint = new QLabel("暂无进程数据\n请先采集进程信息");
        hint->setAlignment(Qt::AlignCenter);
        hint->setStyleSheet("color:#8c8c8c;font-size:12px;padding:20px;");
        lay->insertWidget(0, hint);
    } else {
        int insertPos = 0;
        for (const QVariant &v : rows) {
            QVariantMap m = v.toMap();
            QFrame *card = makeProcessCard(
                m["pid"].toInt(),
                m["name"].toString(),
                m["collected_at"].toString(),
                m["risk"].toString());
            lay->insertWidget(insertPos++, card);
        }
    }
    lay->addStretch();
}

// ─────────────────────────────────────────────────────────────────────────────
// 构建进程树
// ─────────────────────────────────────────────────────────────────────────────
void DynamicScanPage::buildProcessTree(int rootPid) {
    m_chainTree->clear();

    // 查询根进程信息
    auto rootRows = DatabaseManager::instance()->execSelect(
        "SELECT name, risk FROM process_info WHERE pid=? LIMIT 1", {rootPid});
    QString rootName = rootRows.isEmpty() ? QString("PID:%1").arg(rootPid)
                                          : rootRows.first().toMap()["name"].toString();
    QString rootRisk = rootRows.isEmpty() ? "" : rootRows.first().toMap()["risk"].toString();

    auto *rootItem = new QTreeWidgetItem(m_chainTree);
    rootItem->setText(0, rootName);
    rootItem->setText(1, QString::number(rootPid));
    rootItem->setData(0, Qt::UserRole,     rootPid);
    rootItem->setData(0, Qt::UserRole + 1, rootName);
    rootItem->setIcon(0, style()->standardIcon(QStyle::SP_ComputerIcon));

    auto setRiskStyle = [](QTreeWidgetItem *it, const QString &r) {
        if      (r == "high")   { it->setText(2,"高危"); it->setForeground(2,QColor("#f5222d")); it->setForeground(0,QColor("#f5222d")); }
        else if (r == "medium") { it->setText(2,"中危"); it->setForeground(2,QColor("#fa8c16")); }
        else if (r == "low")    { it->setText(2,"低危"); it->setForeground(2,QColor("#1890ff")); }
        else                    { it->setText(2,"正常"); it->setForeground(2,QColor("#52c41a")); }
    };
    setRiskStyle(rootItem, rootRisk);

    // 查询子进程（从 dynamic_scan 的 parent_pid 字段）
    auto rows = DatabaseManager::instance()->execSelect(
        "SELECT DISTINCT pid, source_proc, parent_pid, risk_level "
        "FROM dynamic_scan WHERE parent_pid=? OR pid=? ORDER BY pid",
        {rootPid, rootPid});

    QMap<int, QTreeWidgetItem*> itemMap;
    itemMap[rootPid] = rootItem;
    QSet<int> addedPids;
    addedPids.insert(rootPid);

    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int pid = m["pid"].toInt();
        int parentPid = m["parent_pid"].toInt();
        if (pid == rootPid || addedPids.contains(pid)) continue;
        addedPids.insert(pid);

        QString procName = m["source_proc"].toString();
        if (procName.isEmpty()) procName = QString("PID:%1").arg(pid);
        QString risk = m["risk_level"].toString();

        QTreeWidgetItem *parentItem = itemMap.contains(parentPid) ? itemMap[parentPid] : rootItem;
        auto *item = new QTreeWidgetItem(parentItem);
        item->setText(0, procName);
        item->setText(1, QString::number(pid));
        item->setData(0, Qt::UserRole,     pid);
        item->setData(0, Qt::UserRole + 1, procName);
        item->setIcon(0, style()->standardIcon(QStyle::SP_FileIcon));
        setRiskStyle(item, risk);
        itemMap[pid] = item;
    }

    m_chainTree->expandAll();
}

// ─────────────────────────────────────────────────────────────────────────────
// 加载指定 PID 的行为信息
// ─────────────────────────────────────────────────────────────────────────────
void DynamicScanPage::loadBehaviorForPid(int pid, const QString &procName) {
    m_chainBehavior->setRowCount(0);
    m_lblChainBehaviorTitle->setText(
        QString("  行为信息 — %1 (PID:%2)").arg(procName).arg(pid));

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
        int row = m_chainBehavior->rowCount();
        m_chainBehavior->insertRow(row);
        m_chainBehavior->setItem(row, 0, new QTableWidgetItem(m["scan_time"].toString().mid(11,8)));
        m_chainBehavior->setItem(row, 1, new QTableWidgetItem(
            btypeMap.value(m["behavior_type"].toString(), m["behavior_type"].toString())));
        m_chainBehavior->setItem(row, 2, new QTableWidgetItem(m["action_type"].toString()));
        auto *pi = new QTableWidgetItem(m["target_path"].toString());
        pi->setFont(QFont("Consolas", 11));
        m_chainBehavior->setItem(row, 3, pi);
        m_chainBehavior->setItem(row, 4, new QTableWidgetItem(m["detail"].toString()));
        QString risk = m["risk_level"].toString();
        m_chainBehavior->setItem(row, 5, riskItem(risk));
        highlightRow(m_chainBehavior, row, risk);
    }

    if (rows.isEmpty()) {
        m_chainBehavior->insertRow(0);
        auto *hint = new QTableWidgetItem("暂无该进程的行为记录");
        hint->setForeground(QColor("#8c8c8c"));
        hint->setTextAlignment(Qt::AlignCenter);
        m_chainBehavior->setItem(0, 0, hint);
        m_chainBehavior->setSpan(0, 0, 1, 6);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Slots
// ─────────────────────────────────────────────────────────────────────────────
void DynamicScanPage::refreshData() {
    onQueryBehavior();
    if (m_tabOuter && m_tabOuter->currentIndex() == 1)
        loadProcessCards();
}

void DynamicScanPage::onRefreshProcessChain() {
    loadProcessCards();
    if (m_chainTree) m_chainTree->clear();
    if (m_chainBehavior) m_chainBehavior->setRowCount(0);
    if (m_lblChainBehaviorTitle)
        m_lblChainBehaviorTitle->setText("  行为信息（请点击左侧进程树中的进程）");
    m_selectedRootPid = -1;
}

void DynamicScanPage::onProcessTreeItemClicked(QTreeWidgetItem *item, int) {
    if (!item) return;
    int pid = item->data(0, Qt::UserRole).toInt();
    QString name = item->data(0, Qt::UserRole + 1).toString();
    if (name.isEmpty()) name = item->text(0);
    loadBehaviorForPid(pid, name);
}

void DynamicScanPage::onQueryBehavior() {
    QString kw = m_edtBehaviorKw->text().trimmed();
    int riskIdx = m_cmbBehaviorRisk->currentIndex();
    QStringList riskMap = {"","high","medium","low"};
    QString riskFilter = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";

    queryAndFill(m_tblRegistry,      "registry", kw, riskFilter);
    queryAndFill(m_tblFile,          "file",     kw, riskFilter);
    queryAndFill(m_tblNetwork,       "network",  kw, riskFilter);
    queryAndFill(m_tblSsdt,          "ssdt",     kw, riskFilter);
    queryAndFill(m_tblAutorun,       "autorun",  kw, riskFilter);
    queryAndFill(m_tblTask,          "task",     kw, riskFilter);
    queryAndFill(m_tblBrowserPlugin, "browser",  kw, riskFilter);
    queryAndFill(m_tblProcessDetail, "process",  kw, riskFilter);

    if (m_lblStatus)
        m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void DynamicScanPage::queryAndFill(QTableWidget *tbl, const QString &type,
                                    const QString &kw, const QString &risk) {
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
    sql += " ORDER BY id DESC LIMIT 200";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
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

void DynamicScanPage::onBrowseFile() {
    QString path = QFileDialog::getOpenFileName(this, "选择样本文件", "",
        "可执行文件 (*.exe *.dll *.sys);;所有文件 (*.*)");
    if (!path.isEmpty()) m_editPath->setText(path);
}

void DynamicScanPage::onStartScan() {
    QString path = m_editPath->text().trimmed();
    if (path.isEmpty()) { if (m_lblStatus) m_lblStatus->setText("请先选择样本文件"); return; }
    m_lblMonitorStatus->setText("● 监控中");
    m_lblMonitorStatus->setStyleSheet("font-size:12px;color:#f5222d;font-weight:600;padding:0 8px;");
    if (m_lblStatus) m_lblStatus->setText("正在监控：" + path);
    DatabaseManager::instance()->writeLog(m_role, m_username, "动态行为检测", "开始监控："+path, "success");
}

void DynamicScanPage::onStopScan() {
    m_lblMonitorStatus->setText("● 已停止");
    m_lblMonitorStatus->setStyleSheet("font-size:12px;color:#8c8c8c;font-weight:600;padding:0 8px;");
    if (m_lblStatus) m_lblStatus->setText("监控已停止");
    DatabaseManager::instance()->writeLog(m_role, m_username, "动态行为检测", "停止监控", "success");
}
