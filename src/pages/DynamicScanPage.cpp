#include "pages/DynamicScanPage.h"
#include <QHBoxLayout>
#include <QSplitter>
#include <QFileDialog>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QHeaderView>
#include <QGroupBox>
#include <QTreeWidgetItem>

DynamicScanPage::DynamicScanPage(QWidget *parent)
    : BasePage("动态行为检测", parent)
{
    setupUi();
    refreshData();
}

void DynamicScanPage::setupUi()
{
    // 文件选择行
    QHBoxLayout *fileRow = new QHBoxLayout;
    m_editPath = new QLineEdit;
    m_editPath->setObjectName("searchInput");
    m_editPath->setPlaceholderText("输入样本路径或拖入文件...");
    m_editPath->setText("C:\\Windows\\Temp\\svchost32.exe");
    m_btnBrowse = new QPushButton("浏 览");
    m_btnBrowse->setObjectName("btnSecondary");
    m_btnBrowse->setFixedWidth(72);
    m_btnStart = new QPushButton("开始检测");
    m_btnStart->setObjectName("btnPrimary");
    m_btnStart->setFixedWidth(88);
    m_btnStop = new QPushButton("停止检测");
    m_btnStop->setObjectName("btnWarning");
    m_btnStop->setFixedWidth(88);
    connect(m_btnBrowse, &QPushButton::clicked, this, &DynamicScanPage::onBrowseFile);
    connect(m_btnStart,  &QPushButton::clicked, this, &DynamicScanPage::onStartScan);
    connect(m_btnStop,   &QPushButton::clicked, this, &DynamicScanPage::onStopScan);
    fileRow->addWidget(m_editPath, 1);
    fileRow->addWidget(m_btnBrowse);
    fileRow->addWidget(m_btnStart);
    fileRow->addWidget(m_btnStop);
    m_mainLayout->addLayout(fileRow);

    // 行为分类 Tab
    m_tabBehavior = new QTabWidget;
    m_tabBehavior->setObjectName("behaviorTab");

    // ── 注册表操作 ──
    m_tblRegistry = new QTableWidget(0, 5);
    m_tblRegistry->setHorizontalHeaderLabels({"时间","操作类型","注册表路径","键名","键值/风险"});
    styleTable(m_tblRegistry);
    m_tblRegistry->setColumnWidth(0, 80);
    m_tblRegistry->setColumnWidth(1, 80);
    m_tblRegistry->setColumnWidth(2, 280);
    m_tblRegistry->setColumnWidth(3, 120);
    m_tabBehavior->addTab(m_tblRegistry, "注册表操作");

    // ── 文件行为 ──
    m_tblFile = new QTableWidget(0, 5);
    m_tblFile->setHorizontalHeaderLabels({"时间","操作类型","源路径","目标路径","风险"});
    styleTable(m_tblFile);
    m_tblFile->setColumnWidth(0, 80);
    m_tblFile->setColumnWidth(1, 80);
    m_tabBehavior->addTab(m_tblFile, "文件行为");

    // ── 进程行为（树形 + 详情表）──
    QWidget *procWidget = new QWidget;
    QVBoxLayout *procLay = new QVBoxLayout(procWidget);
    procLay->setContentsMargins(0,0,0,0);
    QLabel *treeLbl = new QLabel("进程关联树");
    treeLbl->setObjectName("sectionLabel");
    procLay->addWidget(treeLbl);
    m_treeProcess = new QTreeWidget;
    m_treeProcess->setObjectName("processTree");
    m_treeProcess->setHeaderLabels({"进程","PID","关系","风险"});
    m_treeProcess->setColumnWidth(0, 260);
    m_treeProcess->setColumnWidth(1, 80);
    m_treeProcess->setColumnWidth(2, 100);
    m_treeProcess->setFixedHeight(140);
    procLay->addWidget(m_treeProcess);
    QLabel *detailLbl = new QLabel("进程行为详情");
    detailLbl->setObjectName("sectionLabel");
    procLay->addWidget(detailLbl);
    m_tblProcessDetail = new QTableWidget(0, 5);
    m_tblProcessDetail->setHorizontalHeaderLabels({"时间","行为类型","源进程","目标进程/参数","风险"});
    styleTable(m_tblProcessDetail);
    procLay->addWidget(m_tblProcessDetail, 1);
    m_tabBehavior->addTab(procWidget, "进程行为");

    // ── 网络行为 ──
    m_tblNetwork = new QTableWidget(0, 6);
    m_tblNetwork->setHorizontalHeaderLabels({"时间","协议","本地端口","远程IP","远程端口","风险"});
    styleTable(m_tblNetwork);
    m_tblNetwork->setColumnWidth(0, 80);
    m_tblNetwork->setColumnWidth(1, 60);
    m_tblNetwork->setColumnWidth(2, 80);
    m_tblNetwork->setColumnWidth(3, 160);
    m_tblNetwork->setColumnWidth(4, 80);
    m_tabBehavior->addTab(m_tblNetwork, "网络行为");

    // ── SSDT操作 ──
    m_tblSsdt = new QTableWidget(0, 4);
    m_tblSsdt->setHorizontalHeaderLabels({"时间","SSDT索引","钩子地址","风险"});
    styleTable(m_tblSsdt);
    m_tabBehavior->addTab(m_tblSsdt, "SSDT操作");

    // ── 启动项操作 ──
    m_tblAutorun = new QTableWidget(0, 4);
    m_tblAutorun->setHorizontalHeaderLabels({"时间","操作类型","注册表路径/路径","风险"});
    styleTable(m_tblAutorun);
    m_tabBehavior->addTab(m_tblAutorun, "启动项操作");

    // ── 计划任务操作 ──
    m_tblTask = new QTableWidget(0, 4);
    m_tblTask->setHorizontalHeaderLabels({"时间","操作类型","任务名称","执行动作/风险"});
    styleTable(m_tblTask);
    m_tabBehavior->addTab(m_tblTask, "计划任务操作");

    // ── 浏览器插件操作 ──
    m_tblBrowserPlugin = new QTableWidget(0, 4);
    m_tblBrowserPlugin->setHorizontalHeaderLabels({"时间","操作类型","浏览器","插件路径/风险"});
    styleTable(m_tblBrowserPlugin);
    m_tabBehavior->addTab(m_tblBrowserPlugin, "浏览器插件操作");

    m_mainLayout->addWidget(m_tabBehavior, 1);
}

void DynamicScanPage::refreshData()
{
    loadBehaviorData("all");
}

void DynamicScanPage::loadBehaviorData(const QString &/*type*/)
{
    // 从 dynamic_scan 表读取数据
    QSqlDatabase db = QSqlDatabase::database("main_conn");

    auto fillTable = [&](QTableWidget *tbl, const QString &behaviorType,
                         const QStringList &cols) {
        tbl->setRowCount(0);
        if (!db.isOpen()) return;
        QSqlQuery q(db);
        q.prepare("SELECT scan_time,action_type,source_proc,target_path,detail,risk_level "
                  "FROM dynamic_scan WHERE behavior_type=? ORDER BY id DESC LIMIT 100");
        q.addBindValue(behaviorType);
        q.exec();
        while (q.next()) {
            int row = tbl->rowCount(); tbl->insertRow(row);
            tbl->setItem(row,0,new QTableWidgetItem(q.value(0).toString().mid(11,8)));
            tbl->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
            if (cols.size() > 2) tbl->setItem(row,2,new QTableWidgetItem(q.value(2).toString()));
            if (cols.size() > 3) tbl->setItem(row,3,new QTableWidgetItem(q.value(3).toString()));
            QString risk = q.value(5).toString();
            if (tbl->columnCount() > (int)cols.size()-1) {
                QTableWidgetItem *ri = new QTableWidgetItem(risk=="high"?"高危":risk=="medium"?"中危":"低危");
                ri->setForeground(risk=="high"?QColor("#ef5350"):risk=="medium"?QColor("#ff9800"):QColor("#42a5f5"));
                ri->setTextAlignment(Qt::AlignCenter);
                tbl->setItem(row, tbl->columnCount()-1, ri);
            }
        }
    };

    fillTable(m_tblRegistry, "registry", {"时间","操作","路径","键名","风险"});
    fillTable(m_tblFile,     "file",     {"时间","操作","源路径","目标路径","风险"});
    fillTable(m_tblNetwork,  "network",  {"时间","协议","本地端口","远程IP","远程端口","风险"});
    fillTable(m_tblSsdt,     "ssdt",     {"时间","索引","地址","风险"});
    fillTable(m_tblAutorun,  "autorun",  {"时间","操作","路径","风险"});
    fillTable(m_tblTask,     "task",     {"时间","操作","任务名","风险"});
    fillTable(m_tblBrowserPlugin,"browser",{"时间","操作","浏览器","路径/风险"});

    // 进程树（从 process 类型数据构建）
    m_treeProcess->clear();
    m_tblProcessDetail->setRowCount(0);

    bool hasData = false;
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.prepare("SELECT scan_time,action_type,source_proc,target_path,detail,risk_level "
                  "FROM dynamic_scan WHERE behavior_type='process' ORDER BY id ASC LIMIT 50");
        q.exec();
        // 主进程节点
        QTreeWidgetItem *root = nullptr;
        while (q.next()) {
            hasData = true;
            if (!root) {
                root = new QTreeWidgetItem(m_treeProcess);
                root->setText(0, q.value(2).toString());
                root->setText(1, "--");
                root->setText(2, "主进程");
                QString risk = q.value(5).toString();
                root->setForeground(3, risk=="high"?QColor("#ef5350"):QColor("#ff9800"));
                root->setText(3, risk=="high"?"高危":"中危");
                m_treeProcess->addTopLevelItem(root);
            }
            QTreeWidgetItem *child = new QTreeWidgetItem(root);
            child->setText(0, q.value(3).toString());
            child->setText(1, "--");
            child->setText(2, q.value(1).toString());
            QString risk = q.value(5).toString();
            child->setForeground(3, risk=="high"?QColor("#ef5350"):QColor("#ff9800"));
            child->setText(3, risk=="high"?"高危":"中危");

            int row = m_tblProcessDetail->rowCount(); m_tblProcessDetail->insertRow(row);
            m_tblProcessDetail->setItem(row,0,new QTableWidgetItem(q.value(0).toString().mid(11,8)));
            m_tblProcessDetail->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
            m_tblProcessDetail->setItem(row,2,new QTableWidgetItem(q.value(2).toString()));
            m_tblProcessDetail->setItem(row,3,new QTableWidgetItem(q.value(3).toString()));
            QTableWidgetItem *ri = new QTableWidgetItem(risk=="high"?"高危":"中危");
            ri->setForeground(risk=="high"?QColor("#ef5350"):QColor("#ff9800"));
            ri->setTextAlignment(Qt::AlignCenter);
            m_tblProcessDetail->setItem(row,4,ri);
        }
        if (root) m_treeProcess->expandAll();
    }

    // 无数据时填充示例
    if (!hasData) {
        // 注册表示例
        if (m_tblRegistry->rowCount() == 0) {
            QList<QStringList> demo = {
                {"09:41:02","添加","HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","WindowsUpdate","C:\\Windows\\Temp\\svchost32.exe -s"},
                {"09:41:05","修改","HKLM\\SYSTEM\\CurrentControlSet\\Services\\","ImagePath","C:\\Windows\\Temp\\svchost32.exe"},
                {"09:41:08","修改","HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","Userinit","C:\\Windows\\system32\\userinit.exe,C:\\Windows\\Temp\\svchost32.exe"},
            };
            for (const QStringList &d : demo) {
                int r = m_tblRegistry->rowCount(); m_tblRegistry->insertRow(r);
                for (int c = 0; c < qMin(d.size(), m_tblRegistry->columnCount()); ++c) {
                    QTableWidgetItem *it = new QTableWidgetItem(d[c]);
                    if (c == m_tblRegistry->columnCount()-1)
                        it->setForeground(QColor("#ef5350"));
                    m_tblRegistry->setItem(r,c,it);
                }
            }
        }
        // 进程树示例
        if (m_treeProcess->topLevelItemCount() == 0) {
            QTreeWidgetItem *root = new QTreeWidgetItem(m_treeProcess);
            root->setText(0, "svchost32.exe (PID: 9012)");
            root->setText(1, "9012"); root->setText(2, "主进程");
            root->setForeground(0, QColor("#ef5350")); root->setText(3, "高危");
            auto addChild = [&](QTreeWidgetItem *p, const QString &name, const QString &pid,
                                const QString &rel, const QString &risk) {
                QTreeWidgetItem *c = new QTreeWidgetItem(p);
                c->setText(0,name); c->setText(1,pid); c->setText(2,rel);
                c->setForeground(0, risk=="高危"?QColor("#ef5350"):QColor("#ff9800"));
                c->setText(3,risk);
            };
            addChild(root,"cmd.exe (PID: 9100)","9100","进程创建","中危");
            addChild(root,"net.exe (PID: 9101)","9101","→ 添加管理员账户","高危");
            addChild(root,"进程注入 → explorer.exe (PID: 1234)","1234","进程注入","高危");
            m_treeProcess->addTopLevelItem(root);
            m_treeProcess->expandAll();

            QList<QStringList> procDemo = {
                {"09:41:10","进程注入","svchost32.exe (9012)","explorer.exe (1234) — CreateRemoteThread","高危"},
                {"09:41:12","进程创建","svchost32.exe (9012)","cmd.exe /c net user hacker Admin@123 /add","高危"},
                {"09:41:15","管道通信","svchost32.exe (9012)","\\\\.\\pipe\\msagent_01","中危"},
            };
            for (const QStringList &d : procDemo) {
                int r = m_tblProcessDetail->rowCount(); m_tblProcessDetail->insertRow(r);
                for (int c = 0; c < d.size(); ++c) {
                    QTableWidgetItem *it = new QTableWidgetItem(d[c]);
                    if (c==4) it->setForeground(d[c]=="高危"?QColor("#ef5350"):QColor("#ff9800"));
                    m_tblProcessDetail->setItem(r,c,it);
                }
            }
        }
        // 网络示例
        if (m_tblNetwork->rowCount() == 0) {
            QList<QStringList> demo = {
                {"09:41:20","TCP","49200","185.220.101.45","4444","高危"},
                {"09:41:35","UDP","53","8.8.8.8","53","低危"},
                {"09:41:50","TCP","49201","192.168.1.254","80","中危"},
            };
            for (const QStringList &d : demo) {
                int r = m_tblNetwork->rowCount(); m_tblNetwork->insertRow(r);
                for (int c = 0; c < d.size(); ++c) {
                    QTableWidgetItem *it = new QTableWidgetItem(d[c]);
                    if (c==5) it->setForeground(d[c]=="高危"?QColor("#ef5350"):d[c]=="中危"?QColor("#ff9800"):QColor("#42a5f5"));
                    m_tblNetwork->setItem(r,c,it);
                }
            }
        }
    }
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void DynamicScanPage::onBrowseFile()
{
    QString path = QFileDialog::getOpenFileName(this, "选择样本文件", "", "可执行文件 (*.exe *.dll *.sys);;所有文件 (*.*)");
    if (!path.isEmpty()) m_editPath->setText(path);
}

void DynamicScanPage::onStartScan()
{
    QString path = m_editPath->text().trimmed();
    if (path.isEmpty()) { m_lblStatus->setText("请先选择样本文件"); return; }
    m_lblStatus->setText("正在动态检测：" + path + " ...");
    DatabaseManager::instance()->writeLog(m_role, m_username, "动态行为检测", "提交样本："+path, "success");
    // 实际项目：调用沙箱/动态分析引擎
    m_lblStatus->setText("已提交动态检测（等待沙箱引擎结果）");
}

void DynamicScanPage::onStopScan()
{
    m_lblStatus->setText("检测已停止");
}
