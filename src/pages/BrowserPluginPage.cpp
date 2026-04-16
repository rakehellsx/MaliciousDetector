#include "pages/BrowserPluginPage.h"
#include "ui_BrowserPluginPage.h"
#include "DatabaseManager.h"
#include <QTableWidgetItem>
#include <QPushButton>
#include <QColor>
#include <QHeaderView>

BrowserPluginPage::BrowserPluginPage(QWidget *parent)
    : BasePage("插件分析", parent)
{
    ui = new Ui::BrowserPluginPage();
    ui->setupUi(this);
    postSetupUi();
    m_tbl        = ui->m_tbl;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbBrowser = ui->m_cmbBrowser;
    m_cmbRisk    = ui->m_cmbRisk;
    m_lblSummary = findChild<QLabel*>("m_lblSummary");
    m_lblStatus  = ui->m_lblStatus;

    m_tbl->horizontalHeader()->setStretchLastSection(true);
    m_tbl->verticalHeader()->setVisible(false);
    m_tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tbl->setAlternatingRowColors(true);

    connect(ui->btnQuery,   &QPushButton::clicked, this, &BrowserPluginPage::onQuery);
    connect(ui->btnRefresh, &QPushButton::clicked, this, &BrowserPluginPage::refreshData);
    connect(ui->btnExport,  &QPushButton::clicked, this, [this]{ m_lblStatus->setText("导出功能开发中..."); });

    refreshData();
}

void BrowserPluginPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbBrowser->setCurrentIndex(0);
    m_cmbRisk->setCurrentIndex(0);
    onQuery();
}

void BrowserPluginPage::onQuery()
{
    QString kw         = m_edtKeyword->text().trimmed();
    int     browserIdx = m_cmbBrowser->currentIndex();
    int     riskIdx    = m_cmbRisk->currentIndex();
    QStringList browserMap = {"", "Chrome", "Firefox", "Edge", "IE"};
    QStringList riskMap    = {"", "高危", "中危", "低危", "正常"};
    QString browser    = (browserIdx > 0 && browserIdx < browserMap.size()) ? browserMap[browserIdx] : "";
    QString riskFilter = (riskIdx   > 0 && riskIdx   < riskMap.size())    ? riskMap[riskIdx]    : "";

    auto rows = DatabaseManager::instance()->execSelect(
        "SELECT browser,name,status,version,modified_time,path,risk FROM browser_plugin ORDER BY risk DESC, browser, id", {});

    if (rows.isEmpty()) { loadDemoData(); return; }

    QVariantList filtered;
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        if (!kw.isEmpty()) {
            bool match = m["name"].toString().contains(kw, Qt::CaseInsensitive)
                      || m["path"].toString().contains(kw, Qt::CaseInsensitive);
            if (!match) continue;
        }
        if (!browser.isEmpty() && m["browser"].toString() != browser) continue;
        if (!riskFilter.isEmpty() && m["risk"].toString() != riskFilter) continue;
        filtered << v;
    }
    fillTable(filtered);
}

void BrowserPluginPage::loadDemoData()
{
    // 列：浏览器 / 插件名称 / 状态 / 版本 / 修改时间 / 路径 / 风险
    struct PlugRow { QString browser, name, status, ver, mtime, path, risk; };
    QList<PlugRow> demo = {
        {"Chrome",  "uBlock Origin",       "已启用", "1.52.0", "2025-10-15",
         "C:\\Users\\user01\\AppData\\Local\\Google\\Chrome\\Extensions\\cjpalhdlnbpafiamejdnhcphjbkeiagm", "正常"},
        {"Chrome",  "Malware Injector",    "已启用", "2.1.0",  "2025-11-18",
         "C:\\Windows\\Temp\\chrome_ext\\malware_ext",                                                     "高危"},
        {"Firefox", "NoScript",            "已启用", "11.4.28","2025-10-01",
         "C:\\Users\\user01\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\extensions\\{73a6fe31}", "正常"},
        {"Edge",    "Microsoft Editor",    "已启用", "1.0.0",  "2025-09-20",
         "C:\\Program Files (x86)\\Microsoft\\Edge\\Extensions\\hokifickgkhplphjiodbggjmoafhignh", "正常"},
        {"Chrome",  "Keylogger Extension", "已启用", "1.0.0",  "2025-11-17",
         "C:\\Windows\\Temp\\chrome_ext\\keylogger",                                                       "高危"},
    };
    m_tbl->setRowCount(0);
    int highRisk = 0;
    for (const auto &d : demo) {
        int r = m_tbl->rowCount(); m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(d.browser));
        m_tbl->setItem(r, 1, new QTableWidgetItem(d.name));
        auto *si = new QTableWidgetItem(d.status);
        si->setForeground(d.status == "已启用" ? QColor("#38a169") : QColor("#718096"));
        si->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 2, si);
        m_tbl->setItem(r, 3, new QTableWidgetItem(d.ver));
        m_tbl->setItem(r, 4, new QTableWidgetItem(d.mtime));
        m_tbl->setItem(r, 5, new QTableWidgetItem(d.path));
        auto *ri = new QTableWidgetItem(d.risk);
        ri->setTextAlignment(Qt::AlignCenter);
        if      (d.risk == "高危") { ri->setForeground(QColor("#e53e3e")); highRisk++; }
        else if (d.risk == "中危")   ri->setForeground(QColor("#dd6b20"));
        else                         ri->setForeground(QColor("#38a169"));
        m_tbl->setItem(r, 6, ri);
        if (d.risk == "高危")
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff5f5"));
    }
    if (m_lblSummary) m_lblSummary->setText(QString("共 %1 个插件，其中高危 %2 个").arg(demo.size()).arg(highRisk));
    m_lblStatus->setText(QString("共 %1 条记录").arg(demo.size()));
}

void BrowserPluginPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    int highRisk = 0;
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount(); m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["browser"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["name"].toString()));
        QString status = m["status"].toString();
        auto *si = new QTableWidgetItem(status);
        si->setForeground(status == "已启用" ? QColor("#38a169") : QColor("#718096"));
        si->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 2, si);
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["version"].toString()));
        m_tbl->setItem(r, 4, new QTableWidgetItem(m["modified_time"].toString()));
        m_tbl->setItem(r, 5, new QTableWidgetItem(m["path"].toString()));
        QString risk = m["risk"].toString();
        auto *ri = new QTableWidgetItem(risk);
        ri->setTextAlignment(Qt::AlignCenter);
        if      (risk == "高危") { ri->setForeground(QColor("#e53e3e")); highRisk++; }
        else if (risk == "中危")   ri->setForeground(QColor("#dd6b20"));
        else                       ri->setForeground(QColor("#38a169"));
        m_tbl->setItem(r, 6, ri);
        if (risk == "高危")
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff5f5"));
    }
    if (m_lblSummary) m_lblSummary->setText(QString("共 %1 个插件，其中高危 %2 个").arg(rows.size()).arg(highRisk));
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}
