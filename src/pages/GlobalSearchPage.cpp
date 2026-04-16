#include "pages/GlobalSearchPage.h"
#include "ui_GlobalSearchPage.h"
#include "DatabaseManager.h"
#include <QHeaderView>
#include <QDateTime>
#include <QFont>
#include <QColor>
#include <QListWidgetItem>
#include <QTextDocument>

GlobalSearchPage::GlobalSearchPage(QWidget *parent)
    : BasePage("全局搜索", parent)
{
    ui = new Ui::GlobalSearchPage();
    ui->setupUi(this);
    postSetupUi();

    // 绑定控件
    m_edtKeyword     = ui->m_edtKeyword;
    m_btnSearch      = ui->m_btnSearch;
    m_btnClear       = ui->m_btnClear;
    m_gbModules      = ui->m_gbModules;
    m_chkAll         = ui->m_chkAll;
    m_chkSysinfo     = ui->m_chkSysinfo;
    m_chkNetwork     = ui->m_chkNetwork;
    m_chkDisk        = ui->m_chkDisk;
    m_chkProcess     = ui->m_chkProcess;
    m_chkPort        = ui->m_chkPort;
    m_chkAutorun     = ui->m_chkAutorun;
    m_chkTask        = ui->m_chkTask;
    m_chkDriver      = ui->m_chkDriver;
    m_chkShared      = ui->m_chkShared;
    m_chkPlugin      = ui->m_chkPlugin;
    m_chkMemory      = ui->m_chkMemory;
    m_chkStatic      = ui->m_chkStatic;
    m_chkDynamic     = ui->m_chkDynamic;
    m_lblSummary     = ui->m_lblSummary;
    m_lstModules     = ui->m_lstModules;
    m_lblModuleTitle = ui->m_lblModuleTitle;
    m_tblResult      = ui->m_tblResult;

    // 搜索按钮样式
    m_btnSearch->setStyleSheet(
        "QPushButton{background:#1a3a6a;color:#fff;border:none;border-radius:3px;padding:6px 20px;font-size:13px;}"
        "QPushButton:hover{background:#2a5a9a;}");
    m_btnClear->setStyleSheet(
        "QPushButton{background:#595959;color:#fff;border:none;border-radius:3px;padding:6px 14px;}"
        "QPushButton:hover{background:#737373;}");

    // 结果表格配置
    m_tblResult->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_tblResult->verticalHeader()->setVisible(false);
    m_tblResult->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tblResult->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tblResult->setAlternatingRowColors(true);

    // 模块列表样式
    m_lstModules->setStyleSheet(
        "QListWidget{border:1px solid #d0d7e3;background:#f8f9fb;}"
        "QListWidget::item{padding:6px 10px;border-bottom:1px solid #e8edf5;}"
        "QListWidget::item:selected{background:#1890ff;color:#fff;}"
        "QListWidget::item:hover{background:#e6f7ff;}");

    // 信号连接
    connect(m_btnSearch,  &QPushButton::clicked, this, &GlobalSearchPage::onSearch);
    connect(m_btnClear,   &QPushButton::clicked, this, &GlobalSearchPage::onClear);
    connect(m_edtKeyword, &QLineEdit::returnPressed, this, &GlobalSearchPage::onSearch);
    connect(m_lstModules, &QListWidget::itemClicked, this, &GlobalSearchPage::onModuleSelected);
    connect(m_chkAll, &QCheckBox::toggled, this, &GlobalSearchPage::onAllToggled);
}

GlobalSearchPage::~GlobalSearchPage() { delete ui; }

void GlobalSearchPage::refreshData() {}

void GlobalSearchPage::onAllToggled(bool checked)
{
    QList<QCheckBox*> boxes = {
        m_chkSysinfo, m_chkNetwork, m_chkDisk, m_chkProcess, m_chkPort,
        m_chkAutorun, m_chkTask, m_chkDriver, m_chkShared, m_chkPlugin,
        m_chkMemory, m_chkStatic, m_chkDynamic
    };
    for (auto *cb : boxes) {
        cb->blockSignals(true);
        cb->setChecked(checked);
        cb->blockSignals(false);
    }
}

void GlobalSearchPage::onSearch()
{
    QString kw = m_edtKeyword->text().trimmed();
    if (kw.isEmpty()) {
        m_lblSummary->setText("请输入搜索关键字");
        return;
    }
    QStringList keywords = kw.split(' ', Qt::SkipEmptyParts);
    doSearch(keywords);
}

void GlobalSearchPage::onClear()
{
    m_edtKeyword->clear();
    m_lstModules->clear();
    m_tblResult->setRowCount(0);
    m_lblSummary->clear();
    m_lblModuleTitle->setText("请在左侧选择模块查看详情");
    m_results.clear();
    if (m_lblStatus) m_lblStatus->clear();
}

void GlobalSearchPage::onModuleSelected(QListWidgetItem *item)
{
    if (!item) return;
    QString moduleId = item->data(Qt::UserRole).toString();
    QStringList keywords = m_edtKeyword->text().trimmed().split(' ', Qt::SkipEmptyParts);
    for (const ModuleResult &mr : m_results) {
        if (mr.moduleId == moduleId) {
            showModuleResult(mr, keywords);
            return;
        }
    }
}

void GlobalSearchPage::doSearch(const QStringList &keywords)
{
    m_results.clear();
    m_lstModules->clear();
    m_tblResult->setRowCount(0);
    m_lblModuleTitle->setText("请在左侧选择模块查看详情");

    // 模块定义：{id, 显示名, SQL, 字段列表}
    struct ModuleDef {
        QString id;
        QString name;
        bool    enabled;
        QString sql;
        QStringList fields;
    };

    QList<ModuleDef> modules = {
        {"sysinfo",  "系统信息",  m_chkSysinfo->isChecked(),
         "SELECT hostname, os_version, cpu, memory, uptime FROM system_info LIMIT 1",
         {"hostname","os_version","cpu","memory","uptime"}},
        {"network",  "网络连接",  m_chkNetwork->isChecked(),
         "SELECT local_addr, remote_addr, state, pid, process_name FROM network_connections",
         {"local_addr","remote_addr","state","pid","process_name"}},
        {"disk",     "硬盘信息",  m_chkDisk->isChecked(),
         "SELECT drive, total, used, free, filesystem FROM disk_info",
         {"drive","total","used","free","filesystem"}},
        {"process",  "进程列表",  m_chkProcess->isChecked(),
         "SELECT name, pid, ppid, path, user, cpu_usage, mem_usage, risk_level FROM process_list",
         {"name","pid","ppid","path","user","cpu_usage","mem_usage","risk_level"}},
        {"port",     "端口监听",  m_chkPort->isChecked(),
         "SELECT protocol, local_port, local_addr, state, pid, process_name FROM port_info",
         {"protocol","local_port","local_addr","state","pid","process_name"}},
        {"autorun",  "自启动项",  m_chkAutorun->isChecked(),
         "SELECT name, path, location, type, risk_level FROM autorun_items",
         {"name","path","location","type","risk_level"}},
        {"task",     "计划任务",  m_chkTask->isChecked(),
         "SELECT name, action, trigger_type, status, risk_level FROM scheduled_tasks",
         {"name","action","trigger_type","status","risk_level"}},
        {"driver",   "驱动信息",  m_chkDriver->isChecked(),
         "SELECT name, path, company, load_order, risk_level FROM driver_info",
         {"name","path","company","load_order","risk_level"}},
        {"shared",   "共享资源",  m_chkShared->isChecked(),
         "SELECT name, path, type, permissions, risk_level FROM shared_resources",
         {"name","path","type","permissions","risk_level"}},
        {"plugin",   "插件分析",  m_chkPlugin->isChecked(),
         "SELECT name, browser, version, path, publisher, risk_level FROM browser_plugins",
         {"name","browser","version","path","publisher","risk_level"}},
        {"memory",   "内存映像",  m_chkMemory->isChecked(),
         "SELECT process_name, pid, base_addr, size, path, risk_level FROM memory_images",
         {"process_name","pid","base_addr","size","path","risk_level"}},
        {"static",   "静态检测",  m_chkStatic->isChecked(),
         "SELECT file_name, file_path, file_hash, risk_level, threat_name FROM static_scan_results",
         {"file_name","file_path","file_hash","risk_level","threat_name"}},
        {"dynamic",  "动态监测",  m_chkDynamic->isChecked(),
         "SELECT time, type, process, target_path, detail, risk FROM dynamic_behaviors",
         {"time","type","process","target_path","detail","risk"}}
    };

    int totalHits = 0;
    for (const ModuleDef &mod : modules) {
        if (!mod.enabled) continue;
        auto rows = searchTable(mod.sql, mod.fields, keywords);
        if (!rows.isEmpty()) {
            ModuleResult mr;
            mr.moduleId   = mod.id;
            mr.moduleName = mod.name;
            mr.rows       = rows;
            m_results.append(mr);
            totalHits += rows.size();

            auto *item = new QListWidgetItem(
                QString("%1  [%2]").arg(mod.name).arg(rows.size()));
            item->setData(Qt::UserRole, mod.id);
            QFont f = item->font(); f.setBold(true); item->setFont(f);
            item->setForeground(QColor("#1890ff"));
            m_lstModules->addItem(item);
        }
    }

    if (totalHits == 0) {
        m_lblSummary->setText("未找到匹配结果");
        if (m_lblStatus) m_lblStatus->setText("搜索完成，无命中");
        return;
    }

    m_lblSummary->setText(QString("共命中 %1 条记录，分布在 %2 个模块")
        .arg(totalHits).arg(m_results.size()));
    if (m_lblStatus)
        m_lblStatus->setText(QString("搜索完成  |  %1")
            .arg(QDateTime::currentDateTime().toString("HH:mm:ss")));

    // 自动展开第一个有结果的模块
    if (!m_results.isEmpty()) {
        m_lstModules->setCurrentRow(0);
        showModuleResult(m_results.first(), keywords);
    }
}

QList<QVariantMap> GlobalSearchPage::searchTable(
    const QString &sql,
    const QStringList &fields,
    const QStringList &keywords,
    const QVariantList &extraBinds)
{
    QList<QVariantMap> result;
    auto rows = DatabaseManager::instance()->execSelect(sql, extraBinds);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        bool hit = false;
        for (const QString &kw : keywords) {
            for (const QString &field : fields) {
                if (m[field].toString().contains(kw, Qt::CaseInsensitive)) {
                    hit = true; break;
                }
            }
            if (hit) break;
        }
        if (hit) {
            QVariantMap row;
            for (const QString &f : fields) row[f] = m[f];
            result.append(row);
        }
    }
    return result;
}

void GlobalSearchPage::showModuleResult(const ModuleResult &mr, const QStringList &keywords)
{
    m_tblResult->setRowCount(0);
    m_lblModuleTitle->setText(mr.moduleName + QString("  —  命中 %1 条").arg(mr.rows.size()));

    if (mr.rows.isEmpty()) return;

    // 动态设置列头
    QStringList colKeys = mr.rows.first().keys();
    m_tblResult->setColumnCount(colKeys.size());
    QStringList headers;
    static const QMap<QString,QString> fieldNames = {
        {"hostname","主机名"},{"os_version","系统版本"},{"cpu","CPU"},
        {"memory","内存"},{"uptime","运行时间"},
        {"local_addr","本地地址"},{"remote_addr","远程地址"},{"state","状态"},
        {"pid","PID"},{"process_name","进程名"},
        {"drive","盘符"},{"total","总容量"},{"used","已用"},{"free","可用"},
        {"filesystem","文件系统"},
        {"name","名称"},{"path","路径"},{"ppid","父PID"},
        {"user","用户"},{"cpu_usage","CPU%"},{"mem_usage","内存%"},
        {"risk_level","风险等级"},{"risk","风险"},
        {"protocol","协议"},{"local_port","本地端口"},
        {"location","位置"},{"type","类型"},
        {"trigger_type","触发类型"},{"action","动作"},{"status","状态"},
        {"company","公司"},{"load_order","加载顺序"},
        {"permissions","权限"},{"browser","浏览器"},
        {"version","版本"},{"publisher","发行商"},
        {"base_addr","基地址"},{"size","大小"},
        {"file_name","文件名"},{"file_path","文件路径"},
        {"file_hash","哈希值"},{"threat_name","威胁名称"},
        {"time","时间"},{"target_path","目标路径"},{"detail","详情"},
        {"process","进程"},{"process_name","进程名"}
    };
    for (const QString &k : colKeys)
        headers << fieldNames.value(k, k);
    m_tblResult->setHorizontalHeaderLabels(headers);
    m_tblResult->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    if (!colKeys.isEmpty())
        m_tblResult->horizontalHeader()->setSectionResizeMode(
            colKeys.size() - 1, QHeaderView::Stretch);

    for (const QVariantMap &rowData : mr.rows) {
        int row = m_tblResult->rowCount();
        m_tblResult->insertRow(row);
        for (int c = 0; c < colKeys.size(); c++) {
            QString val = rowData[colKeys[c]].toString();
            QString hl  = highlightText(val, keywords);
            auto *item = new QTableWidgetItem();
            item->setData(Qt::DisplayRole, val);
            // 若有高亮，用 tooltip 标注
            if (hl != val) {
                item->setBackground(QColor("#fffbe6"));
                item->setToolTip("命中关键字：" + keywords.join(", "));
                QFont f = item->font(); f.setBold(true); item->setFont(f);
                item->setForeground(QColor("#d4380d"));
            }
            m_tblResult->setItem(row, c, item);
        }
    }
}

QString GlobalSearchPage::highlightText(const QString &text, const QStringList &keywords)
{
    QString result = text;
    for (const QString &kw : keywords) {
        if (text.contains(kw, Qt::CaseInsensitive))
            return text; // 有命中
    }
    return result;
}
