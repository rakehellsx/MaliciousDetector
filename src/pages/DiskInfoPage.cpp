#include "pages/DiskInfoPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

DiskInfoPage::DiskInfoPage(QWidget *parent)
    : BasePage("硬盘信息", parent)
{
    setupUi();
    refreshData();
}

void DiskInfoPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    toolRow->setSpacing(6);

    m_edtKeyword = new QLineEdit;
    m_edtKeyword->setPlaceholderText("盘符 / 文件系统 / 序列号");
    m_edtKeyword->setClearButtonEnabled(true);
    m_edtKeyword->setFixedWidth(200);
    connect(m_edtKeyword, &QLineEdit::returnPressed, this, &DiskInfoPage::onQuery);

    m_cmbType = new QComboBox;
    m_cmbType->addItems({"全部类型", "本地磁盘", "可移动磁盘", "网络磁盘", "光驱"});
    connect(m_cmbType, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &DiskInfoPage::onQuery);

    QPushButton *btnQuery   = new QPushButton("查询");
    btnQuery->setObjectName("btnPrimary");
    btnQuery->setFixedWidth(70);
    connect(btnQuery, &QPushButton::clicked, this, &DiskInfoPage::onQuery);

    QPushButton *btnRefresh = new QPushButton("刷新");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(70);
    connect(btnRefresh, &QPushButton::clicked, this, &DiskInfoPage::refreshData);

    toolRow->addWidget(new QLabel("关键字："));
    toolRow->addWidget(m_edtKeyword);
    toolRow->addSpacing(8);
    toolRow->addWidget(new QLabel("类型："));
    toolRow->addWidget(m_cmbType);
    toolRow->addWidget(btnQuery);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    m_lblStatus = new QLabel;
    m_lblStatus->setObjectName("statusLabel");
    m_mainLayout->addWidget(m_lblStatus);

    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"盘符", "类型", "文件系统", "总大小(GB)", "可用(GB)", "使用率", "序列号"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl, 1);
}

void DiskInfoPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbType->setCurrentIndex(0);
    onQuery();
}

void DiskInfoPage::onQuery()
{
    QString kw   = m_edtKeyword->text().trimmed();
    int     tIdx = m_cmbType->currentIndex();
    QStringList typeMap = {"", "本地磁盘", "可移动磁盘", "网络磁盘", "光驱"};
    QString typeFilter  = (tIdx > 0 && tIdx < typeMap.size()) ? typeMap[tIdx] : "";

    QString sql = "SELECT drive,type,filesystem,total_gb,free_gb,used_pct,serial FROM disk_info WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (drive LIKE ? OR filesystem LIKE ? OR serial LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like;
    }
    if (!typeFilter.isEmpty()) {
        sql += " AND type = ?";
        binds << typeFilter;
    }
    sql += " ORDER BY id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}

void DiskInfoPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["drive"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["type"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["filesystem"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(QString::number(m["total_gb"].toDouble(), 'f', 1)));
        m_tbl->setItem(r, 4, new QTableWidgetItem(QString::number(m["free_gb"].toDouble(), 'f', 1)));
        double pct = m["used_pct"].toDouble();
        auto *usage = new QTableWidgetItem(QString::number(pct, 'f', 1) + "%");
        if      (pct > 90) usage->setForeground(QColor("#ef5350"));
        else if (pct > 70) usage->setForeground(QColor("#ff9800"));
        else               usage->setForeground(QColor("#4caf50"));
        m_tbl->setItem(r, 5, usage);
        m_tbl->setItem(r, 6, new QTableWidgetItem(m["serial"].toString()));
    }
}
