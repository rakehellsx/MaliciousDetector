#include "pages/NetworkInfoPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
NetworkInfoPage::NetworkInfoPage(QWidget *parent)
    : BasePage("\u7f51\u7edc\u4fe1\u606f", parent)
{
    setupUi();
    refreshData();
}
void NetworkInfoPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    QPushButton *btnRefresh = new QPushButton("\u5237\u65b0");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(80);
    connect(btnRefresh, &QPushButton::clicked, this, &NetworkInfoPage::refreshData);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);
    m_tbl = new QTableWidget(0, 6);
    m_tbl->setHorizontalHeaderLabels({"\u9002\u914d\u5668\u540d", "IP\u5730\u5740", "\u5b50\u7f51\u63a9\u7801", "\u7f51\u5173", "MAC\u5730\u5740", "\u72b6\u6001"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl, 1);
}
void NetworkInfoPage::refreshData()
{
    m_tbl->setRowCount(0);
    auto rows = DatabaseManager::instance()->queryNetInfo();
    for (const QVariant &_var : rows) { QVariantMap m = _var.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["ip"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["mask"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["gateway"].toString()));
        m_tbl->setItem(r, 4, new QTableWidgetItem(m["mac"].toString()));
        QString status = m["status"].toString();
        QTableWidgetItem *si = new QTableWidgetItem(status);
        si->setForeground(status == "\u5df2\u8fde\u63a5" ? QColor("#4caf50") : QColor("#90caf9"));
        si->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 5, si);
    }
    m_lblStatus->setText(QString("\u5171 %1 \u4e2a\u9002\u914d\u5668").arg(m_tbl->rowCount()));
}
