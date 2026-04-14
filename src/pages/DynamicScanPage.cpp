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
    m_editPath->setText("C:\\Windows\\Temp\\svchost32.exe");
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

    // 无数据时填充演示数据
    if (!hasData) {
        // 注册表
        struct RegDemo { QString time,op,path,val,risk; };
        QList<RegDemo> regData = {
            {"09:41:02","写入","HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate","C:\\Windows\\Temp\\svchost32.exe -s","high"},
            {"09:41:05","读取","HKLM\\SYSTEM\\CurrentControlSet\\Services","—","medium"},
            {"09:41:08","读取","HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer","—","low"},
            {"09:41:12","写入","HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe","Debugger=C:\\Windows\\Temp\\svchost32.exe","high"},
        };
        for (const auto &d : regData) {
            int r = m_tblRegistry->rowCount(); m_tblRegistry->insertRow(r);
            m_tblRegistry->setItem(r,0,new QTableWidgetItem(d.time));
            m_tblRegistry->setItem(r,1,new QTableWidgetItem(d.op));
            QTableWidgetItem *pi = new QTableWidgetItem(d.path);
            pi->setFont(QFont("Consolas",11));
            m_tblRegistry->setItem(r,2,pi);
            QTableWidgetItem *vi = new QTableWidgetItem(d.val);
            vi->setFont(QFont("Consolas",11));
            m_tblRegistry->setItem(r,3,vi);
            m_tblRegistry->setItem(r,4,riskItem(d.risk));
            highlightRow(m_tblRegistry,r,d.risk);
        }

        // 文件行为
        struct FileDemo { QString time,op,path,risk; };
        QList<FileDemo> fileData = {
            {"09:41:03","创建","C:\\Windows\\Temp\\payload.dll","high"},
            {"09:41:04","读取","C:\\Windows\\System32\\drivers\\etc\\hosts","medium"},
            {"09:41:06","读取","C:\\Users\\user01\\AppData\\Roaming\\Microsoft\\Windows\\Recent","low"},
            {"09:41:15","修改","C:\\Windows\\System32\\drivers\\etc\\hosts","high"},
        };
        for (const auto &d : fileData) {
            int r = m_tblFile->rowCount(); m_tblFile->insertRow(r);
            m_tblFile->setItem(r,0,new QTableWidgetItem(d.time));
            m_tblFile->setItem(r,1,new QTableWidgetItem(d.op));
            QTableWidgetItem *pi = new QTableWidgetItem(d.path);
            pi->setFont(QFont("Consolas",11));
            m_tblFile->setItem(r,2,pi);
            m_tblFile->setItem(r,3,riskItem(d.risk));
            highlightRow(m_tblFile,r,d.risk);
        }

        // 进程树
        QTreeWidgetItem *root = new QTreeWidgetItem(m_treeProcess);
        root->setText(0,"svchost32.exe"); root->setText(1,"9012");
        root->setText(2,"目标样本 | 高危"); root->setText(3,"高危");
        root->setForeground(0,QColor("#f5222d")); root->setForeground(3,QColor("#f5222d"));
        m_treeProcess->addTopLevelItem(root);

        QTreeWidgetItem *cmd = new QTreeWidgetItem(root);
        cmd->setText(0,"cmd.exe"); cmd->setText(1,"9100");
        cmd->setText(2,"执行系统命令"); cmd->setText(3,"高危");
        cmd->setForeground(0,QColor("#f5222d")); cmd->setForeground(3,QColor("#f5222d"));

        QTreeWidgetItem *who = new QTreeWidgetItem(cmd);
        who->setText(0,"whoami.exe"); who->setText(1,"9101");
        who->setText(2,"枚举当前用户"); who->setText(3,"注意");
        who->setForeground(3,QColor("#fa8c16"));

        QTreeWidgetItem *net = new QTreeWidgetItem(cmd);
        net->setText(0,"net.exe"); net->setText(1,"9102");
        net->setText(2,"枚举用户账户"); net->setText(3,"注意");
        net->setForeground(3,QColor("#fa8c16"));

        QTreeWidgetItem *ps = new QTreeWidgetItem(root);
        ps->setText(0,"powershell.exe"); ps->setText(1,"9200");
        ps->setText(2,"-WindowStyle Hidden -enc [base64]"); ps->setText(3,"高危");
        ps->setForeground(0,QColor("#f5222d")); ps->setForeground(3,QColor("#f5222d"));
        m_treeProcess->expandAll();

        struct ProcDemo { QString time,op,target,pid,risk; };
        QList<ProcDemo> procData = {
            {"09:41:10","注入","explorer.exe","1234","high"},
            {"09:41:11","创建","cmd.exe","9100","high"},
            {"09:41:16","创建","powershell.exe","9200","medium"},
        };
        for (const auto &d : procData) {
            int r = m_tblProcessDetail->rowCount(); m_tblProcessDetail->insertRow(r);
            m_tblProcessDetail->setItem(r,0,new QTableWidgetItem(d.time));
            m_tblProcessDetail->setItem(r,1,new QTableWidgetItem(d.op));
            m_tblProcessDetail->setItem(r,2,new QTableWidgetItem(d.target));
            m_tblProcessDetail->setItem(r,3,new QTableWidgetItem(d.pid));
            m_tblProcessDetail->setItem(r,4,riskItem(d.risk));
            highlightRow(m_tblProcessDetail,r,d.risk);
        }

        // 网络行为
        struct NetDemo { QString time,proto,local,remote,data,risk; };
        QList<NetDemo> netData = {
            {"09:41:20","TCP","192.168.1.100:49152","185.220.101.45:4444","↑2.1KB ↓0.8KB","high"},
            {"09:41:22","DNS","192.168.1.100:52341","8.8.8.8:53","↑0.1KB","medium"},
            {"09:41:35","HTTP","192.168.1.100:49200","185.220.101.45:80","↑0.5KB ↓12.3KB","high"},
        };
        for (const auto &d : netData) {
            int r = m_tblNetwork->rowCount(); m_tblNetwork->insertRow(r);
            m_tblNetwork->setItem(r,0,new QTableWidgetItem(d.time));
            m_tblNetwork->setItem(r,1,new QTableWidgetItem(d.proto));
            QTableWidgetItem *li = new QTableWidgetItem(d.local);
            li->setFont(QFont("Consolas",11));
            m_tblNetwork->setItem(r,2,li);
            QTableWidgetItem *ri2 = new QTableWidgetItem(d.remote);
            ri2->setFont(QFont("Consolas",11));
            m_tblNetwork->setItem(r,3,ri2);
            m_tblNetwork->setItem(r,4,new QTableWidgetItem(d.data));
            m_tblNetwork->setItem(r,5,riskItem(d.risk));
            highlightRow(m_tblNetwork,r,d.risk);
        }

        // SSDT
        struct SsdtDemo { QString time,idx,func,addr,mod,risk; };
        QList<SsdtDemo> ssdtData = {
            {"09:41:30","#0x002B","NtCreateFile","0xFFFFF88003A01234","hiddrv.sys（未签名）","high"},
            {"09:41:31","#0x0077","NtQuerySystemInformation","0xFFFFF88003A01890","hiddrv.sys（未签名）","high"},
        };
        for (const auto &d : ssdtData) {
            int r = m_tblSsdt->rowCount(); m_tblSsdt->insertRow(r);
            m_tblSsdt->setItem(r,0,new QTableWidgetItem(d.time));
            m_tblSsdt->setItem(r,1,new QTableWidgetItem(d.idx));
            m_tblSsdt->setItem(r,2,new QTableWidgetItem(d.func));
            QTableWidgetItem *ai = new QTableWidgetItem(d.addr);
            ai->setFont(QFont("Consolas",11));
            m_tblSsdt->setItem(r,3,ai);
            m_tblSsdt->setItem(r,4,new QTableWidgetItem(d.mod));
            m_tblSsdt->setItem(r,5,riskItem(d.risk));
            highlightRow(m_tblSsdt,r,d.risk);
        }

        // 启动项操作
        {
            int r = m_tblAutorun->rowCount(); m_tblAutorun->insertRow(r);
            m_tblAutorun->setItem(r,0,new QTableWidgetItem("09:41:02"));
            m_tblAutorun->setItem(r,1,new QTableWidgetItem("新增"));
            m_tblAutorun->setItem(r,2,new QTableWidgetItem("WindowsUpdate"));
            QTableWidgetItem *vi = new QTableWidgetItem("HKCU\\...\\Run = C:\\Windows\\Temp\\svchost32.exe -s");
            vi->setFont(QFont("Consolas",11));
            m_tblAutorun->setItem(r,3,vi);
            m_tblAutorun->setItem(r,4,riskItem("high"));
            highlightRow(m_tblAutorun,r,"high");
        }

        // 计划任务操作
        {
            int r = m_tblTask->rowCount(); m_tblTask->insertRow(r);
            m_tblTask->setItem(r,0,new QTableWidgetItem("09:41:25"));
            m_tblTask->setItem(r,1,new QTableWidgetItem("创建"));
            m_tblTask->setItem(r,2,new QTableWidgetItem("UpdateTask"));
            m_tblTask->setItem(r,3,new QTableWidgetItem("每5分钟"));
            QTableWidgetItem *ei = new QTableWidgetItem("C:\\Windows\\Temp\\payload.exe");
            ei->setFont(QFont("Consolas",11));
            m_tblTask->setItem(r,4,ei);
            m_tblTask->setItem(r,5,riskItem("high"));
            highlightRow(m_tblTask,r,"high");
        }

        // 浏览器插件操作
        {
            int r = m_tblBrowserPlugin->rowCount(); m_tblBrowserPlugin->insertRow(r);
            m_tblBrowserPlugin->setItem(r,0,new QTableWidgetItem("09:41:40"));
            m_tblBrowserPlugin->setItem(r,1,new QTableWidgetItem("安装"));
            m_tblBrowserPlugin->setItem(r,2,new QTableWidgetItem("Chrome"));
            m_tblBrowserPlugin->setItem(r,3,new QTableWidgetItem("Flash Player Helper"));
            QTableWidgetItem *pi = new QTableWidgetItem("C:\\Users\\user01\\AppData\\Local\\Google\\Chrome\\Extensions\\aabbccddeeff");
            pi->setFont(QFont("Consolas",11));
            m_tblBrowserPlugin->setItem(r,4,pi);
            m_tblBrowserPlugin->setItem(r,5,riskItem("high"));
            highlightRow(m_tblBrowserPlugin,r,"high");
        }
    }

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
