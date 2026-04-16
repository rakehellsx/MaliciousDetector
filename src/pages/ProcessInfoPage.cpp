#include "pages/ProcessInfoPage.h"
#include "ui_ProcessInfoPage.h"

#include "DatabaseManager.h"
#include <QTableWidgetItem>
#include <QPushButton>
#include <QColor>
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QLabel>
#include <QDialogButtonBox>
#include <QHeaderView>

ProcessInfoPage::ProcessInfoPage(QWidget *parent)
    : BasePage("进程列表", parent)
{
    ui = new Ui::ProcessInfoPage();
    ui->setupUi(this);
    postSetupUi();

    m_tbl        = ui->m_tbl;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbRisk    = ui->m_cmbRisk;
    m_cmbStatus  = ui->m_cmbStatus;
    m_lblStatus  = ui->m_lblStatus;

    m_tbl->horizontalHeader()->setStretchLastSection(true);
    m_tbl->verticalHeader()->setVisible(false);

    connect(ui->btnQuery,   &QPushButton::clicked, this, &ProcessInfoPage::onQuery);
    connect(ui->btnRefresh, &QPushButton::clicked, this, &ProcessInfoPage::refreshData);
    connect(ui->btnExport,  &QPushButton::clicked, this, [this]{ m_lblStatus->setText("导出功能开发中..."); });

    refreshData();
}

void ProcessInfoPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbRisk->setCurrentIndex(0);
    m_cmbStatus->setCurrentIndex(0);
    onQuery();
}

void ProcessInfoPage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     riskIdx = m_cmbRisk->currentIndex();
    int     stIdx   = m_cmbStatus->currentIndex();
    QStringList riskMap = {"", "高危", "中危", "低危", "正常"};
    QStringList stMap   = {"", "运行中", "已停止", "僵尸"};
    QString risk   = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";
    QString status = (stIdx   > 0 && stIdx   < stMap.size())   ? stMap[stIdx]   : "";

    auto rows = DatabaseManager::instance()->execSelect(
        "SELECT pid,name,path,publisher,cpu_pct,mem_mb,threads,risk,status FROM process_info WHERE 1=1 ORDER BY risk DESC, cpu_pct DESC",
        {});

    if (rows.isEmpty()) {
        loadDemoData();
        return;
    }

    QVariantList filtered;
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        if (!kw.isEmpty()) {
            bool match = m["name"].toString().contains(kw, Qt::CaseInsensitive)
                      || m["path"].toString().contains(kw, Qt::CaseInsensitive);
            if (!match) continue;
        }
        if (!risk.isEmpty()   && m["risk"].toString()   != risk)   continue;
        if (!status.isEmpty() && m["status"].toString() != status) continue;
        filtered << v;
    }
    fillTable(filtered);
}

// 演示数据（与原型 prototype_v5.html 完全一致）
void ProcessInfoPage::loadDemoData()
{
    struct ProcRow {
        QString pid, name, path, publisher, cpu, mem, threads, risk;
    };
    QList<ProcRow> demo = {
        {"1234", "explorer.exe",  "C:\\Windows\\explorer.exe",               "Microsoft Corporation", "1.2",  "48.5",  "12", "正常"},
        {"892",  "svchost.exe",   "C:\\Windows\\System32\\svchost.exe",       "Microsoft Corporation", "0.8",  "32.1",  "8",  "正常"},
        {"3421", "wuauclt32.exe", "C:\\Windows\\System32\\wuauclt32.exe",     "未知",                  "15.3", "128.7", "5",  "中危"},
        {"4892", "chrome.exe",    "C:\\Program Files\\Google\\Chrome\\chrome.exe", "Google LLC",       "8.5",  "256.3", "24", "正常"},
        {"5671", "svchost32.exe", "C:\\Windows\\Temp\\svchost32.exe",         "未知",                  "45.2", "512.8", "3",  "高危"},
        {"2341", "notepad.exe",   "C:\\Windows\\System32\\notepad.exe",       "Microsoft Corporation", "0.1",  "8.2",   "2",  "正常"},
    };

    m_tbl->setRowCount(0);
    for (const auto &d : demo) {
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);

        // PID
        auto *pidItem = new QTableWidgetItem(d.pid);
        pidItem->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 0, pidItem);

        // 进程名（高危/中危着色）
        auto *nm = new QTableWidgetItem(d.name);
        if      (d.risk == "高危") nm->setForeground(QColor("#e53e3e"));
        else if (d.risk == "中危") nm->setForeground(QColor("#dd6b20"));
        m_tbl->setItem(r, 1, nm);

        // 映像路径
        m_tbl->setItem(r, 2, new QTableWidgetItem(d.path));

        // 发行商
        auto *pub = new QTableWidgetItem(d.publisher);
        if (d.publisher == "未知") pub->setForeground(QColor("#718096"));
        m_tbl->setItem(r, 3, pub);

        // CPU%
        auto *cpu = new QTableWidgetItem(d.cpu + "%");
        cpu->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 4, cpu);

        // 内存(MB)
        auto *mem = new QTableWidgetItem(d.mem + " MB");
        mem->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 5, mem);

        // 线程数
        auto *thr = new QTableWidgetItem(d.threads);
        thr->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 6, thr);

        // 风险
        auto *ri = new QTableWidgetItem(d.risk);
        ri->setTextAlignment(Qt::AlignCenter);
        if      (d.risk == "高危") { ri->setForeground(QColor("#e53e3e")); ri->setBackground(QColor("#fff5f5")); }
        else if (d.risk == "中危") { ri->setForeground(QColor("#dd6b20")); ri->setBackground(QColor("#fffaf0")); }
        else                       { ri->setForeground(QColor("#38a169")); }
        m_tbl->setItem(r, 7, ri);

        // 详情按钮
        auto *btn = new QPushButton("详情");
        btn->setProperty("procName", d.name);
        btn->setProperty("procPid",  d.pid);
        btn->setProperty("procPath", d.path);
        btn->setProperty("procPub",  d.publisher);
        btn->setProperty("procCpu",  d.cpu);
        btn->setProperty("procMem",  d.mem);
        btn->setProperty("procThr",  d.threads);
        btn->setProperty("procRisk", d.risk);
        btn->setStyleSheet("QPushButton{background:#3182ce;color:white;border:none;border-radius:3px;padding:2px 8px;font-size:12px;}"
                           "QPushButton:hover{background:#2b6cb0;}");
        connect(btn, &QPushButton::clicked, this, &ProcessInfoPage::onDetailClicked);
        m_tbl->setCellWidget(r, 8, btn);

        // 高危行整体背景
        if (d.risk == "高危")
            for (int c = 0; c < 8; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff5f5"));
    }
    m_lblStatus->setText(QString("共 %1 条记录").arg(demo.size()));
}

void ProcessInfoPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);

        auto *pidItem = new QTableWidgetItem(m["pid"].toString());
        pidItem->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 0, pidItem);

        QString risk = m["risk"].toString();
        auto *nm = new QTableWidgetItem(m["name"].toString());
        if      (risk == "高危") nm->setForeground(QColor("#e53e3e"));
        else if (risk == "中危") nm->setForeground(QColor("#dd6b20"));
        m_tbl->setItem(r, 1, nm);

        m_tbl->setItem(r, 2, new QTableWidgetItem(m["path"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["publisher"].toString()));

        auto *cpu = new QTableWidgetItem(QString::number(m["cpu_pct"].toDouble(), 'f', 1) + "%");
        cpu->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 4, cpu);

        auto *mem = new QTableWidgetItem(QString::number(m["mem_mb"].toDouble(), 'f', 1) + " MB");
        mem->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 5, mem);

        auto *thr = new QTableWidgetItem(m["threads"].toString());
        thr->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 6, thr);

        auto *ri = new QTableWidgetItem(risk);
        ri->setTextAlignment(Qt::AlignCenter);
        if      (risk == "高危") { ri->setForeground(QColor("#e53e3e")); }
        else if (risk == "中危") { ri->setForeground(QColor("#dd6b20")); }
        else                     { ri->setForeground(QColor("#38a169")); }
        m_tbl->setItem(r, 7, ri);

        auto *btn = new QPushButton("详情");
        btn->setProperty("procName", m["name"].toString());
        btn->setProperty("procPid",  m["pid"].toString());
        btn->setProperty("procPath", m["path"].toString());
        btn->setProperty("procPub",  m["publisher"].toString());
        btn->setProperty("procCpu",  QString::number(m["cpu_pct"].toDouble(), 'f', 1));
        btn->setProperty("procMem",  QString::number(m["mem_mb"].toDouble(), 'f', 1));
        btn->setProperty("procThr",  m["threads"].toString());
        btn->setProperty("procRisk", risk);
        btn->setStyleSheet("QPushButton{background:#3182ce;color:white;border:none;border-radius:3px;padding:2px 8px;font-size:12px;}"
                           "QPushButton:hover{background:#2b6cb0;}");
        connect(btn, &QPushButton::clicked, this, &ProcessInfoPage::onDetailClicked);
        m_tbl->setCellWidget(r, 8, btn);
    }
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}

// 进程详情弹窗（含基本信息/模块/线程/文件句柄 四个Tab）
void ProcessInfoPage::onDetailClicked()
{
    auto *btn = qobject_cast<QPushButton*>(sender());
    if (!btn) return;

    QString name  = btn->property("procName").toString();
    QString pid   = btn->property("procPid").toString();
    QString path  = btn->property("procPath").toString();
    QString pub   = btn->property("procPub").toString();
    QString cpu   = btn->property("procCpu").toString();
    QString mem   = btn->property("procMem").toString();
    QString thr   = btn->property("procThr").toString();
    QString risk  = btn->property("procRisk").toString();

    QDialog dlg(this);
    dlg.setWindowTitle(QString("进程详情 — %1  PID:%2").arg(name, pid));
    dlg.resize(760, 520);

    auto *mainLay = new QVBoxLayout(&dlg);
    mainLay->setContentsMargins(12, 12, 12, 8);

    // 标题栏
    auto *titleLay = new QHBoxLayout;
    auto *titleLbl = new QLabel(QString("<b>%1</b>  <span style='color:#718096'>PID: %2</span>").arg(name, pid));
    titleLbl->setStyleSheet("font-size:14px;");
    titleLay->addWidget(titleLbl);
    titleLay->addStretch();
    if (risk == "高危") {
        auto *badge = new QLabel("高危");
        badge->setStyleSheet("background:#e53e3e;color:white;border-radius:3px;padding:2px 8px;font-size:12px;");
        titleLay->addWidget(badge);
    } else if (risk == "中危") {
        auto *badge = new QLabel("中危");
        badge->setStyleSheet("background:#dd6b20;color:white;border-radius:3px;padding:2px 8px;font-size:12px;");
        titleLay->addWidget(badge);
    }
    mainLay->addLayout(titleLay);

    // Tab 页
    auto *tabs = new QTabWidget;
    mainLay->addWidget(tabs, 1);

    // ── Tab1: 基本信息 ──
    auto *tabBasic = new QWidget;
    auto *gridLay  = new QHBoxLayout(tabBasic);
    auto *col1 = new QVBoxLayout;
    auto *col2 = new QVBoxLayout;

    auto addKV = [](QVBoxLayout *col, const QString &k, const QString &v) {
        auto *row = new QHBoxLayout;
        auto *kl = new QLabel(k + "：");
        kl->setStyleSheet("color:#4a5568;font-size:12px;min-width:80px;");
        kl->setAlignment(Qt::AlignRight | Qt::AlignTop);
        auto *vl = new QLabel(v);
        vl->setStyleSheet("font-size:12px;color:#1a202c;");
        vl->setWordWrap(true);
        row->addWidget(kl);
        row->addWidget(vl, 1);
        col->addLayout(row);
    };

    addKV(col1, "进程名",   name);
    addKV(col1, "PID",      pid);
    addKV(col1, "映像路径", path);
    addKV(col1, "发行商",   pub);
    addKV(col1, "CPU使用",  cpu + "%");
    addKV(col2, "内存",     mem + " MB");
    addKV(col2, "线程数",   thr);
    addKV(col2, "风险等级", risk);
    addKV(col2, "授信状态", pub.contains("Microsoft") || pub.contains("Google") ? "已签名" : "未签名");
    addKV(col2, "创建时间", "2025-11-20 08:01:23");

    col1->addStretch();
    col2->addStretch();
    gridLay->addLayout(col1, 1);
    gridLay->addLayout(col2, 1);
    tabs->addTab(tabBasic, "基本信息");

    // ── Tab2: 模块 ──
    auto *tabMod = new QWidget;
    auto *modLay = new QVBoxLayout(tabMod);
    auto *modTbl = new QTableWidget(0, 6);
    modTbl->setHorizontalHeaderLabels({"模块名称","映像路径","发行商","修改时间","大小","授信状态"});
    modTbl->horizontalHeader()->setStretchLastSection(true);
    modTbl->verticalHeader()->setVisible(false);
    modTbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    modTbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    modTbl->setAlternatingRowColors(true);

    struct ModRow { QString name, path, pub, mtime, size, trust; };
    QList<ModRow> mods = {
        {"ntdll.dll",    "C:\\Windows\\System32\\ntdll.dll",    "Microsoft Corporation", "2025-10-01", "1.97 MB", "已签名"},
        {"kernel32.dll", "C:\\Windows\\System32\\kernel32.dll", "Microsoft Corporation", "2025-10-01", "0.97 MB", "已签名"},
        {"user32.dll",   "C:\\Windows\\System32\\user32.dll",   "Microsoft Corporation", "2025-10-01", "1.54 MB", "已签名"},
    };
    if (risk == "高危") {
        mods << ModRow{"inject.dll", "C:\\Windows\\Temp\\inject.dll", "未知", "2025-11-19", "0.12 MB", "未签名"};
        mods << ModRow{"payload.dll","C:\\Windows\\Temp\\payload.dll","未知", "2025-11-19", "0.08 MB", "未签名"};
    }
    for (const auto &m : mods) {
        int r = modTbl->rowCount(); modTbl->insertRow(r);
        modTbl->setItem(r, 0, new QTableWidgetItem(m.name));
        modTbl->setItem(r, 1, new QTableWidgetItem(m.path));
        modTbl->setItem(r, 2, new QTableWidgetItem(m.pub));
        modTbl->setItem(r, 3, new QTableWidgetItem(m.mtime));
        modTbl->setItem(r, 4, new QTableWidgetItem(m.size));
        auto *ti = new QTableWidgetItem(m.trust);
        ti->setForeground(m.trust == "已签名" ? QColor("#38a169") : QColor("#e53e3e"));
        ti->setTextAlignment(Qt::AlignCenter);
        modTbl->setItem(r, 5, ti);
    }
    modLay->addWidget(modTbl);
    tabs->addTab(tabMod, "模块");

    // ── Tab3: 线程 ──
    auto *tabThr = new QWidget;
    auto *thrLay = new QVBoxLayout(tabThr);
    auto *thrTbl = new QTableWidget(0, 7);
    thrTbl->setHorizontalHeaderLabels({"线程ID","状态","优先级","CPU%","入口地址","所属模块","创建时间"});
    thrTbl->horizontalHeader()->setStretchLastSection(true);
    thrTbl->verticalHeader()->setVisible(false);
    thrTbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    thrTbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    thrTbl->setAlternatingRowColors(true);

    struct ThrRow { QString tid, status, prio, cpu, addr, mod, ctime; };
    QList<ThrRow> thrs = {
        {"0x1A2B", "运行", "普通",  "1.2", "0x77A12340", "ntdll.dll",    "2025-11-20 08:01"},
        {"0x1A2C", "等待", "普通",  "0.0", "0x77A12380", "kernel32.dll", "2025-11-20 08:01"},
        {"0x1A2D", "等待", "低",    "0.0", "0x77A123C0", "user32.dll",   "2025-11-20 08:01"},
    };
    for (const auto &t : thrs) {
        int r = thrTbl->rowCount(); thrTbl->insertRow(r);
        thrTbl->setItem(r, 0, new QTableWidgetItem(t.tid));
        auto *si = new QTableWidgetItem(t.status);
        si->setForeground(t.status == "运行" ? QColor("#38a169") : QColor("#718096"));
        si->setTextAlignment(Qt::AlignCenter);
        thrTbl->setItem(r, 1, si);
        thrTbl->setItem(r, 2, new QTableWidgetItem(t.prio));
        thrTbl->setItem(r, 3, new QTableWidgetItem(t.cpu + "%"));
        thrTbl->setItem(r, 4, new QTableWidgetItem(t.addr));
        thrTbl->setItem(r, 5, new QTableWidgetItem(t.mod));
        thrTbl->setItem(r, 6, new QTableWidgetItem(t.ctime));
    }
    thrLay->addWidget(thrTbl);
    tabs->addTab(tabThr, "线程");

    // ── Tab4: 文件句柄 ──
    auto *tabHdl = new QWidget;
    auto *hdlLay = new QVBoxLayout(tabHdl);
    auto *hdlTbl = new QTableWidget(0, 4);
    hdlTbl->setHorizontalHeaderLabels({"句柄值","类型","访问权限","路径/目标"});
    hdlTbl->horizontalHeader()->setStretchLastSection(true);
    hdlTbl->verticalHeader()->setVisible(false);
    hdlTbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    hdlTbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    hdlTbl->setAlternatingRowColors(true);

    struct HdlRow { QString val, type, access, target; };
    QList<HdlRow> hdls = {
        {"0x0004", "文件",   "读取",     "C:\\Windows\\System32\\ntdll.dll"},
        {"0x0008", "注册表", "读写",     "HKLM\\SOFTWARE\\Microsoft\\Windows NT"},
        {"0x000C", "进程",   "全部访问", "PID:892 svchost.exe"},
        {"0x0010", "套接字", "读写",     risk == "高危" ? "185.220.101.45:4444" : "127.0.0.1:80"},
        {"0x0014", "文件",   "读写",     "C:\\Users\\user01\\AppData\\Local\\Temp\\tmp.dat"},
    };
    for (const auto &h : hdls) {
        int r = hdlTbl->rowCount(); hdlTbl->insertRow(r);
        hdlTbl->setItem(r, 0, new QTableWidgetItem(h.val));
        auto *ti = new QTableWidgetItem(h.type);
        QColor tc = h.type == "文件" ? QColor("#3182ce") :
                    h.type == "注册表" ? QColor("#805ad5") :
                    h.type == "套接字" ? QColor("#d69e2e") : QColor("#718096");
        ti->setForeground(tc);
        ti->setTextAlignment(Qt::AlignCenter);
        hdlTbl->setItem(r, 1, ti);
        hdlTbl->setItem(r, 2, new QTableWidgetItem(h.access));
        auto *pi = new QTableWidgetItem(h.target);
        if (h.target.contains("185.220")) pi->setForeground(QColor("#e53e3e"));
        hdlTbl->setItem(r, 3, pi);
    }
    hdlLay->addWidget(hdlTbl);
    tabs->addTab(tabHdl, "文件句柄");

    // 关闭按钮
    auto *btnBox = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(btnBox, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    mainLay->addWidget(btnBox);

    dlg.exec();
}
