#include "pages/SystemInfoPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
SystemInfoPage::SystemInfoPage(QWidget *parent)
    : BasePage("\u7cfb\u7edf\u57fa\u672c\u4fe1\u606f", parent)
{
    setupUi();
    refreshData();
}
void SystemInfoPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    QPushButton *btnRefresh = new QPushButton("\u5237\u65b0");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(80);
    connect(btnRefresh, &QPushButton::clicked, this, &SystemInfoPage::refreshData);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);
    m_tbl = new QTableWidget(0, 2);
    m_tbl->setHorizontalHeaderLabels({"\u5c5e\u6027", "\u5024"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
    m_tbl->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_tbl->setColumnWidth(0, 160);
    m_mainLayout->addWidget(m_tbl, 1);
}
void SystemInfoPage::refreshData()
{
    m_tbl->setRowCount(0);
    auto rows = DatabaseManager::instance()->querySysInfo();
    for (const QVariant &_var : rows) { QVariantMap m = _var.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["key"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["value"].toString()));
    }
    m_lblStatus->setText(QString("\u5171 %1 \u9879").arg(m_tbl->rowCount()));
}
