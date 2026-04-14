#include "pages/PortInfoPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>

PortInfoPage::PortInfoPage(QWidget *parent)
    : BasePage("\u7aef\u53e3\u4fe1\u606f", parent)
{
    setupUi();
    refreshData();
}

void PortInfoPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    m_cmbProto = new QComboBox;
    m_cmbProto->addItems({"\u5168\u90e8\u534f\u8bae", "TCP", "UDP"});
    connect(m_cmbProto, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &PortInfoPage::onProtoFilter);
    QPushButton *btnRefresh = new QPushButton("\u5237\u65b0");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(80);
    connect(btnRefresh, &QPushButton::clicked, this, &PortInfoPage::refreshData);
    toolRow->addWidget(new QLabel("\u534f\u8bae:"));
    toolRow->addWidget(m_cmbProto);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    // DB字段: protocol, local_ip, local_port, remote_ip, remote_port, state, process_name, pid, risk
    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"\u534f\u8bae", "\u672c\u5730IP", "\u672c\u5730\u7aef\u53e3", "\u8fdc\u7a0b\u5730\u5740:\u7aef\u53e3", "\u72b6\u6001", "\u8fdb\u7a0b", "\u98ce\u9669"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl, 1);
}

void PortInfoPage::refreshData()
{
    m_allRows.clear();
    auto rows = DatabaseManager::instance()->queryPortInfo();
    for (const QVariant &_v : rows) m_allRows.append(_v.toMap());
    onProtoFilter(m_cmbProto->currentIndex());
    m_lblStatus->setText(QString("\u5171 %1 \u4e2a\u8fde\u63a5").arg(m_allRows.size()));
}

void PortInfoPage::onProtoFilter(int idx)
{
    m_tbl->setRowCount(0);
    QString filter = idx == 1 ? "TCP" : idx == 2 ? "UDP" : "";
    for (const QVariantMap &m : m_allRows) {
        if (!filter.isEmpty() && m["protocol"].toString() != filter) continue;
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["protocol"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["local_ip"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["local_port"].toString()));
        // 远程地址:端口合并显示
        QString remoteAddr = m["remote_ip"].toString();
        if (!m["remote_port"].toString().isEmpty() && m["remote_port"].toString() != "0")
            remoteAddr += ":" + m["remote_port"].toString();
        m_tbl->setItem(r, 3, new QTableWidgetItem(remoteAddr));
        // 状态着色
        QString state = m["state"].toString();
        auto *st = new QTableWidgetItem(state);
        if (state == "LISTEN")           st->setForeground(QColor("#4caf50"));
        else if (state == "ESTABLISHED") st->setForeground(QColor("#42a5f5"));
        else if (state == "TIME_WAIT")   st->setForeground(QColor("#ff9800"));
        st->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 4, st);
        m_tbl->setItem(r, 5, new QTableWidgetItem(m["process_name"].toString()));
        // 风险着色
        QString risk = m["risk"].toString();
        auto *ri = new QTableWidgetItem(risk);
        if (risk == "\u9ad8\u5371") ri->setForeground(QColor("#ef5350"));
        else if (risk == "\u4e2d\u5371") ri->setForeground(QColor("#ff9800"));
        else ri->setForeground(QColor("#4caf50"));
        ri->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 6, ri);
        // 高危行背景
        if (risk == "\u9ad8\u5371")
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff1f0"));
    }
}
