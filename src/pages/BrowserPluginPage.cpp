#include "pages/BrowserPluginPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

BrowserPluginPage::BrowserPluginPage(QWidget *parent)
    : BasePage("浏览器插件", parent)
{
    setupUi();
    refreshData();
}

void BrowserPluginPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    toolRow->setSpacing(6);

    m_edtKeyword = new QLineEdit;
    m_edtKeyword->setPlaceholderText("插件名 / 发布商 / 版本");
    m_edtKeyword->setClearButtonEnabled(true);
    m_edtKeyword->setFixedWidth(200);
    connect(m_edtKeyword, &QLineEdit::returnPressed, this, &BrowserPluginPage::onQuery);

    m_cmbBrowser = new QComboBox;
    m_cmbBrowser->addItems({"全部浏览器", "Chrome", "Firefox", "Edge", "IE"});
    connect(m_cmbBrowser, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &BrowserPluginPage::onQuery);

    m_cmbRisk = new QComboBox;
    m_cmbRisk->addItems({"全部风险", "高危", "中危", "低危"});
    connect(m_cmbRisk, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &BrowserPluginPage::onQuery);

    QPushButton *btnQuery   = new QPushButton("查询");
    btnQuery->setObjectName("btnPrimary");
    btnQuery->setFixedWidth(70);
    connect(btnQuery, &QPushButton::clicked, this, &BrowserPluginPage::onQuery);

    QPushButton *btnRefresh = new QPushButton("刷新");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(70);
    connect(btnRefresh, &QPushButton::clicked, this, &BrowserPluginPage::refreshData);

    toolRow->addWidget(new QLabel("关键字："));
    toolRow->addWidget(m_edtKeyword);
    toolRow->addSpacing(8);
    toolRow->addWidget(new QLabel("浏览器："));
    toolRow->addWidget(m_cmbBrowser);
    toolRow->addSpacing(8);
    toolRow->addWidget(new QLabel("风险："));
    toolRow->addWidget(m_cmbRisk);
    toolRow->addWidget(btnQuery);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    m_lblSummary = new QLabel;
    m_lblSummary->setObjectName("summaryLabel");
    m_mainLayout->addWidget(m_lblSummary);

    m_lblStatus = new QLabel;
    m_lblStatus->setObjectName("statusLabel");
    m_mainLayout->addWidget(m_lblStatus);

    // DB字段: browser, name, version, publisher, status, risk
    m_tbl = new QTableWidget(0, 6);
    m_tbl->setHorizontalHeaderLabels({"浏览器", "插件名称", "版本", "发布商", "状态", "风险"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl, 1);
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
    QStringList riskMap    = {"", "高危", "中危", "低危"};
    QString browser    = (browserIdx > 0 && browserIdx < browserMap.size()) ? browserMap[browserIdx] : "";
    QString riskFilter = (riskIdx   > 0 && riskIdx   < riskMap.size())    ? riskMap[riskIdx]    : "";

    QString sql = "SELECT browser,name,version,publisher,status,risk FROM browser_plugin WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (name LIKE ? OR publisher LIKE ? OR version LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like;
    }
    if (!browser.isEmpty()) {
        sql += " AND browser = ?";
        binds << browser;
    }
    if (!riskFilter.isEmpty()) {
        sql += " AND risk = ?";
        binds << riskFilter;
    }
    sql += " ORDER BY risk DESC, browser, id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);

    int highRisk = 0;
    for (const QVariant &v : rows)
        if (v.toMap()["risk"].toString() == "高危") highRisk++;
    m_lblSummary->setText(QString("共 %1 个插件，其中高危 %2 个").arg(rows.size()).arg(highRisk));
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}

void BrowserPluginPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["browser"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["name"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["version"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["publisher"].toString()));
        QString status = m["status"].toString();
        QTableWidgetItem *si = new QTableWidgetItem(status);
        si->setForeground(status.contains("启用") ? QColor("#4caf50") : QColor("#90caf9"));
        si->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 4, si);
        QString risk = m["risk"].toString();
        auto *ri = new QTableWidgetItem(risk);
        if      (risk == "高危") ri->setForeground(QColor("#ef5350"));
        else if (risk == "中危") ri->setForeground(QColor("#ff9800"));
        else                     ri->setForeground(QColor("#4caf50"));
        ri->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 5, ri);
        if (risk == "高危")
            for (int c = 0; c < 6; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff1f0"));
    }
}
