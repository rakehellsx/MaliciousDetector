#include "pages/ProcessInfoPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
ProcessInfoPage::ProcessInfoPage(QWidget *parent)
    : BasePage("\u8fdb\u7a0b\u4fe1\u606f", parent)
{
    setupUi();
    refreshData();
}
void ProcessInfoPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    m_edtSearch = new QLineEdit;
    m_edtSearch->setPlaceholderText("\u641c\u7d22\u8fdb\u7a0b\u540d...");
    m_edtSearch->setFixedWidth(200);
    connect(m_edtSearch, &QLineEdit::textChanged, this, &ProcessInfoPage::filterTable);
    QPushButton *btnRefresh = new QPushButton("\u5237\u65b0");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(80);
    connect(btnRefresh, &QPushButton::clicked, this, &ProcessInfoPage::refreshData);
    toolRow->addWidget(m_edtSearch);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);
    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"PID", "\u8fdb\u7a0b\u540d", "\u8def\u5f84", "CPU%", "\u5185\u5b58(MB)", "\u7528\u6237", "\u72b6\u6001"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_tbl->setColumnWidth(0, 60);
    m_tbl->setColumnWidth(3, 60);
    m_tbl->setColumnWidth(4, 80);
    m_mainLayout->addWidget(m_tbl, 1);
}
void ProcessInfoPage::refreshData()
{
    m_allRows.clear();
    m_tbl->setRowCount(0);
    auto rows = DatabaseManager::instance()->queryProcessInfo();
    for (const QVariant &_v : rows) m_allRows.append(_v.toMap());
    filterTable(m_edtSearch->text());
    m_lblStatus->setText(QString("\u5171 %1 \u4e2a\u8fdb\u7a0b").arg(m_allRows.size()));
}
void ProcessInfoPage::filterTable(const QString &kw)
{
    m_tbl->setRowCount(0);
    for (const QVariantMap &m : m_allRows) {
        if (!kw.isEmpty() && !m["name"].toString().contains(kw, Qt::CaseInsensitive)) continue;
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["pid"].toString()));
        auto *nm = new QTableWidgetItem(m["name"].toString());
        // risk字段：高危进程标红
        if (m["risk"].toString() == "\u9ad8\u5371") nm->setForeground(QColor("#ef5350"));
        else if (m["risk"].toString() == "\u4e2d\u5371") nm->setForeground(QColor("#ff9800"));
        m_tbl->setItem(r, 1, nm);
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["path"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(QString::number(m["cpu_pct"].toDouble(), 'f', 1)));
        m_tbl->setItem(r, 4, new QTableWidgetItem(QString::number(m["mem_mb"].toDouble(), 'f', 1)));
        m_tbl->setItem(r, 5, new QTableWidgetItem(m["user"].toString()));
        auto *st = new QTableWidgetItem(m["status"].toString());
        st->setForeground(m["status"].toString() == "\u8fd0\u884c\u4e2d" ? QColor("#4caf50") : QColor("#90caf9"));
        st->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 6, st);
    }
}
