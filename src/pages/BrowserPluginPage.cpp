#include "pages/BrowserPluginPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>

BrowserPluginPage::BrowserPluginPage(QWidget *parent)
    : BasePage("\u6d4f\u89c8\u5668\u63d2\u4ef6", parent)
{
    setupUi();
    refreshData();
}

void BrowserPluginPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    m_cmbBrowser = new QComboBox;
    m_cmbBrowser->addItems({"\u5168\u90e8\u6d4f\u89c8\u5668", "Chrome", "Firefox", "Edge", "IE"});
    connect(m_cmbBrowser, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &BrowserPluginPage::onBrowserFilter);
    QPushButton *btnRefresh = new QPushButton("\u5237\u65b0");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(80);
    connect(btnRefresh, &QPushButton::clicked, this, &BrowserPluginPage::refreshData);
    toolRow->addWidget(new QLabel("\u6d4f\u89c8\u5668:"));
    toolRow->addWidget(m_cmbBrowser);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);
    m_lblSummary = new QLabel;
    m_lblSummary->setObjectName("summaryLabel");
    m_mainLayout->addWidget(m_lblSummary);

    // DB字段: browser, name, version, publisher, status, risk
    m_tbl = new QTableWidget(0, 6);
    m_tbl->setHorizontalHeaderLabels({"\u63d2\u4ef6\u540d\u79f0", "\u6d4f\u89c8\u5668", "\u7248\u672c", "\u53d1\u5e03\u5546", "\u72b6\u6001", "\u98ce\u9669"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl, 1);
}

void BrowserPluginPage::refreshData()
{
    m_allPlugins.clear();
    auto rows = DatabaseManager::instance()->queryBrowserPlugins();
    for (const QVariant &_v : rows) m_allPlugins.append(_v.toMap());
    onBrowserFilter(m_cmbBrowser->currentIndex());
    int high = 0;
    for (const QVariantMap &m : m_allPlugins)
        if (m["risk"].toString() == "\u9ad8\u5371") high++;
    m_lblSummary->setText(QString("\u5171 %1 \u4e2a\u63d2\u4ef6\uff0c\u9ad8\u5371 %2 \u4e2a").arg(m_allPlugins.size()).arg(high));
    m_lblStatus->setText(QString("\u5171 %1 \u6761\u8bb0\u5f55").arg(m_allPlugins.size()));
}

void BrowserPluginPage::onBrowserFilter(int idx)
{
    m_tbl->setRowCount(0);
    QStringList browserMap = {"", "Chrome", "Firefox", "Edge", "IE"};
    QString filter = (idx > 0 && idx < browserMap.size()) ? browserMap[idx] : "";
    for (const QVariantMap &m : m_allPlugins) {
        if (!filter.isEmpty() && m["browser"].toString() != filter) continue;
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["browser"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["version"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["publisher"].toString()));
        // status字段直接显示（如"已启用"/"已禁用"等）
        QString status = m["status"].toString();
        QTableWidgetItem *si = new QTableWidgetItem(status);
        si->setForeground(status.contains("\u542f\u7528") ? QColor("#4caf50") : QColor("#90caf9"));
        si->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 4, si);
        // 风险着色
        QString risk = m["risk"].toString();
        auto *ri = new QTableWidgetItem(risk);
        if (risk == "\u9ad8\u5371") ri->setForeground(QColor("#ef5350"));
        else if (risk == "\u4e2d\u5371") ri->setForeground(QColor("#ff9800"));
        else ri->setForeground(QColor("#4caf50"));
        ri->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 5, ri);
        // 高危行背景
        if (risk == "\u9ad8\u5371")
            for (int c = 0; c < 6; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff1f0"));
    }
}
