#include "pages/DiskInfoPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>

DiskInfoPage::DiskInfoPage(QWidget *parent)
    : BasePage("\u786c\u76d8\u4fe1\u606f", parent)
{
    setupUi();
    refreshData();
}

void DiskInfoPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    QPushButton *btnRefresh = new QPushButton("\u5237\u65b0");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(80);
    connect(btnRefresh, &QPushButton::clicked, this, &DiskInfoPage::refreshData);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    // DB字段: drive, type, filesystem, total_gb, free_gb, used_pct, serial
    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"\u76d8\u7b26", "\u7c7b\u578b", "\u6587\u4ef6\u7cfb\u7edf", "\u603b\u5927\u5c0f(GB)", "\u53ef\u7528(GB)", "\u4f7f\u7528\u7387", "\u5e8f\u5217\u53f7"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl, 1);
}

void DiskInfoPage::refreshData()
{
    m_tbl->setRowCount(0);
    auto rows = DatabaseManager::instance()->queryDiskInfo();
    for (const QVariant &_var : rows) {
        QVariantMap m = _var.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["drive"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["type"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["filesystem"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(QString::number(m["total_gb"].toDouble(), 'f', 1)));
        m_tbl->setItem(r, 4, new QTableWidgetItem(QString::number(m["free_gb"].toDouble(), 'f', 1)));
        double pct = m["used_pct"].toDouble();
        auto *usage = new QTableWidgetItem(QString::number(pct, 'f', 1) + "%");
        if (pct > 90) usage->setForeground(QColor("#ef5350"));
        else if (pct > 70) usage->setForeground(QColor("#ff9800"));
        else usage->setForeground(QColor("#4caf50"));
        m_tbl->setItem(r, 5, usage);
        m_tbl->setItem(r, 6, new QTableWidgetItem(m["serial"].toString()));
    }
    m_lblStatus->setText(QString("\u5171 %1 \u4e2a\u5206\u533a").arg(m_tbl->rowCount()));
}
