#include "pages/DriverInfoPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>

DriverInfoPage::DriverInfoPage(QWidget *parent)
    : BasePage("\u9a71\u52a8\u4fe1\u606f", parent)
{
    setupUi();
    refreshData();
}

void DriverInfoPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    m_cmbType = new QComboBox;
    m_cmbType->addItems({"\u5168\u90e8\u7c7b\u578b", "\u5185\u6838\u9a71\u52a8", "\u8bbe\u5907\u9a71\u52a8", "\u7b2c\u4e09\u65b9"});
    connect(m_cmbType, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &DriverInfoPage::onTypeFilter);
    QPushButton *btnRefresh = new QPushButton("\u5237\u65b0");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(80);
    connect(btnRefresh, &QPushButton::clicked, this, &DriverInfoPage::refreshData);
    toolRow->addWidget(new QLabel("\u7c7b\u578b:"));
    toolRow->addWidget(m_cmbType);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);
    m_lblSummary = new QLabel;
    m_lblSummary->setObjectName("summaryLabel");
    m_mainLayout->addWidget(m_lblSummary);

    // DB字段: name, type, publisher, modified_time, path, is_signed, risk
    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"\u9a71\u52a8\u540d\u79f0", "\u7c7b\u578b", "\u53d1\u5e03\u5546", "\u4fee\u6539\u65f6\u95f4", "\u6587\u4ef6\u8def\u5f84", "\u6570\u5b57\u7b7e\u540d", "\u98ce\u9669"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl, 1);
}

void DriverInfoPage::refreshData()
{
    m_allDrivers.clear();
    auto rows = DatabaseManager::instance()->queryDriverInfo();
    for (const QVariant &_v : rows) m_allDrivers.append(_v.toMap());
    onTypeFilter(m_cmbType->currentIndex());
    int high = 0;
    for (const QVariantMap &m : m_allDrivers)
        if (m["risk"].toString() == "\u9ad8\u5371") high++;
    m_lblSummary->setText(QString("\u5171 %1 \u4e2a\u9a71\u52a8\uff0c\u9ad8\u5371 %2 \u4e2a").arg(m_allDrivers.size()).arg(high));
    m_lblStatus->setText(QString("\u5171 %1 \u6761\u8bb0\u5f55").arg(m_allDrivers.size()));
}

void DriverInfoPage::onTypeFilter(int idx)
{
    m_tbl->setRowCount(0);
    QStringList typeMap = {"", "\u5185\u6838\u9a71\u52a8", "\u8bbe\u5907\u9a71\u52a8", "\u7b2c\u4e09\u65b9"};
    QString filter = (idx > 0 && idx < typeMap.size()) ? typeMap[idx] : "";
    for (const QVariantMap &m : m_allDrivers) {
        if (!filter.isEmpty() && m["type"].toString() != filter) continue;
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["type"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["publisher"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["modified_time"].toString()));
        m_tbl->setItem(r, 4, new QTableWidgetItem(m["path"].toString()));
        // is_signed: 1=已签名, 0=未签名
        bool isSigned = m["is_signed"].toInt() != 0;
        QTableWidgetItem *si = new QTableWidgetItem(isSigned ? "\u5df2\u7b7e\u540d" : "\u672a\u7b7e\u540d");
        si->setForeground(isSigned ? QColor("#4caf50") : QColor("#f5222d"));
        QFont sf = si->font(); sf.setBold(true); si->setFont(sf);
        si->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 5, si);
        // 风险着色
        QString risk = m["risk"].toString();
        auto *ri = new QTableWidgetItem(risk);
        if (risk == "\u9ad8\u5371") ri->setForeground(QColor("#ef5350"));
        else if (risk == "\u4e2d\u5371") ri->setForeground(QColor("#ff9800"));
        else ri->setForeground(QColor("#4caf50"));
        ri->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 6, ri);
        // 高危行背景
        if (risk == "\u9ad8\u5371" || !isSigned)
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff1f0"));
    }
}
