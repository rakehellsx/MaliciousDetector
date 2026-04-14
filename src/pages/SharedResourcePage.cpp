#include "pages/SharedResourcePage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>

SharedResourcePage::SharedResourcePage(QWidget *parent)
    : BasePage("\u5171\u4eab\u8d44\u6e90", parent)
{
    setupUi();
    refreshData();
}

void SharedResourcePage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    QPushButton *btnRefresh = new QPushButton("\u5237\u65b0");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(80);
    connect(btnRefresh, &QPushButton::clicked, this, &SharedResourcePage::refreshData);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    // DB字段: name, path, type, permission, connected, risk
    m_tbl = new QTableWidget(0, 6);
    m_tbl->setHorizontalHeaderLabels({"\u5171\u4eab\u540d", "\u672c\u5730\u8def\u5f84", "\u7c7b\u578b", "\u6743\u9650", "\u5df2\u8fde\u63a5", "\u98ce\u9669"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl, 1);
}

void SharedResourcePage::refreshData()
{
    m_tbl->setRowCount(0);
    auto rows = DatabaseManager::instance()->querySharedResources();
    for (const QVariant &_var : rows) {
        QVariantMap m = _var.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["path"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["type"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["permission"].toString()));
        // connected: 0=未连接, 非0=已连接
        bool connected = m["connected"].toInt() > 0;
        QTableWidgetItem *ci = new QTableWidgetItem(connected ? "\u662f" : "\u5426");
        ci->setForeground(connected ? QColor("#f5222d") : QColor("#4caf50"));
        ci->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 4, ci);
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
    m_lblStatus->setText(QString("\u5171 %1 \u4e2a\u5171\u4eab\u8d44\u6e90").arg(m_tbl->rowCount()));
}
