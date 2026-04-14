#include "pages/ScheduledTaskPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
ScheduledTaskPage::ScheduledTaskPage(QWidget *parent)
    : BasePage("\u8ba1\u5212\u4efb\u52a1", parent)
{
    setupUi();
    refreshData();
}
void ScheduledTaskPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    QPushButton *btnRefresh = new QPushButton("\u5237\u65b0");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(80);
    connect(btnRefresh, &QPushButton::clicked, this, &ScheduledTaskPage::refreshData);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);
    m_lblSummary = new QLabel;
    m_lblSummary->setObjectName("summaryLabel");
    m_mainLayout->addWidget(m_lblSummary);
    // DB字段: name, path, trigger, action, status, last_run, risk
    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"\u4efb\u52a1\u540d\u79f0", "\u89e6\u53d1\u65b9\u5f0f", "\u6267\u884c\u547d\u4ee4", "\u8def\u5f84", "\u72b6\u6001", "\u4e0a\u6b21\u8fd0\u884c", "\u98ce\u9669"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl, 1);
}
void ScheduledTaskPage::refreshData()
{
    m_tbl->setRowCount(0);
    auto rows = DatabaseManager::instance()->queryScheduledTasks();
    int highRisk = 0;
    for (const QVariant &_var : rows) { QVariantMap m = _var.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["trigger"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["action"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["path"].toString()));
        m_tbl->setItem(r, 4, new QTableWidgetItem(m["status"].toString()));
        m_tbl->setItem(r, 5, new QTableWidgetItem(m["last_run"].toString()));
        auto *risk = new QTableWidgetItem(m["risk"].toString());
        if (m["risk"].toString() == "\u9ad8\u5371") { risk->setForeground(QColor("#ef5350")); highRisk++; }
        else if (m["risk"].toString() == "\u4e2d\u5371") risk->setForeground(QColor("#ff9800"));
        else risk->setForeground(QColor("#4caf50"));
        risk->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 6, risk);
        if (m["risk"].toString() == "\u9ad8\u5371")
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff1f0"));
    }
    m_lblSummary->setText(QString("\u5171 %1 \u4e2a\u8ba1\u5212\u4efb\u52a1\uff0c\u5176\u4e2d\u9ad8\u5371 %2 \u4e2a").arg(rows.size()).arg(highRisk));
    m_lblStatus->setText(QString("\u5171 %1 \u6761\u8bb0\u5f55").arg(rows.size()));
}
