#include "pages/NetworkInfoPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

NetworkInfoPage::NetworkInfoPage(QWidget *parent)
    : BasePage("网络信息", parent)
{
    setupUi();
    refreshData();
}

void NetworkInfoPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    toolRow->setSpacing(6);

    // 关键字搜索（name / ip / mac / gateway）
    m_edtKeyword = new QLineEdit;
    m_edtKeyword->setPlaceholderText("适配器名 / IP / MAC / 网关");
    m_edtKeyword->setClearButtonEnabled(true);
    m_edtKeyword->setFixedWidth(220);
    connect(m_edtKeyword, &QLineEdit::returnPressed, this, &NetworkInfoPage::onQuery);

    // 状态下拉
    m_cmbStatus = new QComboBox;
    m_cmbStatus->addItems({"全部状态", "已连接", "断开"});
    connect(m_cmbStatus, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &NetworkInfoPage::onQuery);

    QPushButton *btnQuery   = new QPushButton("查询");
    btnQuery->setObjectName("btnPrimary");
    btnQuery->setFixedWidth(70);
    connect(btnQuery, &QPushButton::clicked, this, &NetworkInfoPage::onQuery);

    QPushButton *btnRefresh = new QPushButton("刷新");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(70);
    connect(btnRefresh, &QPushButton::clicked, this, &NetworkInfoPage::refreshData);

    toolRow->addWidget(new QLabel("关键字："));
    toolRow->addWidget(m_edtKeyword);
    toolRow->addSpacing(8);
    toolRow->addWidget(new QLabel("状态："));
    toolRow->addWidget(m_cmbStatus);
    toolRow->addWidget(btnQuery);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    m_lblStatus = new QLabel;
    m_lblStatus->setObjectName("statusLabel");
    m_mainLayout->addWidget(m_lblStatus);

    m_tbl = new QTableWidget(0, 6);
    m_tbl->setHorizontalHeaderLabels({"适配器名", "IP地址", "子网掩码", "网关", "MAC地址", "状态"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl, 1);
}

void NetworkInfoPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbStatus->setCurrentIndex(0);
    onQuery();
}

void NetworkInfoPage::onQuery()
{
    QString kw     = m_edtKeyword->text().trimmed();
    int     stIdx  = m_cmbStatus->currentIndex();
    QString status = stIdx == 1 ? "已连接" : stIdx == 2 ? "断开" : "";

    QString sql = "SELECT name,ip,mask,gateway,mac,status FROM net_info WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (name LIKE ? OR ip LIKE ? OR mac LIKE ? OR gateway LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like << like;
    }
    if (!status.isEmpty()) {
        sql += " AND status = ?";
        binds << status;
    }
    sql += " ORDER BY id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}

void NetworkInfoPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["ip"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["mask"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["gateway"].toString()));
        m_tbl->setItem(r, 4, new QTableWidgetItem(m["mac"].toString()));
        QString st = m["status"].toString();
        auto *si = new QTableWidgetItem(st);
        si->setForeground(st == "已连接" ? QColor("#4caf50") : QColor("#90caf9"));
        si->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 5, si);
    }
}
