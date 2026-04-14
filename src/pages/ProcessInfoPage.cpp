#include "pages/ProcessInfoPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

ProcessInfoPage::ProcessInfoPage(QWidget *parent)
    : BasePage("进程信息", parent)
{
    setupUi();
    refreshData();
}

void ProcessInfoPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    toolRow->setSpacing(6);

    m_edtKeyword = new QLineEdit;
    m_edtKeyword->setPlaceholderText("进程名 / 路径 / 用户");
    m_edtKeyword->setClearButtonEnabled(true);
    m_edtKeyword->setFixedWidth(220);
    connect(m_edtKeyword, &QLineEdit::returnPressed, this, &ProcessInfoPage::onQuery);

    m_cmbRisk = new QComboBox;
    m_cmbRisk->addItems({"全部风险", "高危", "中危", "低危"});
    connect(m_cmbRisk, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ProcessInfoPage::onQuery);

    m_cmbStatus = new QComboBox;
    m_cmbStatus->addItems({"全部状态", "运行中", "已停止", "挂起"});
    connect(m_cmbStatus, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ProcessInfoPage::onQuery);

    QPushButton *btnQuery   = new QPushButton("查询");
    btnQuery->setObjectName("btnPrimary");
    btnQuery->setFixedWidth(70);
    connect(btnQuery, &QPushButton::clicked, this, &ProcessInfoPage::onQuery);

    QPushButton *btnRefresh = new QPushButton("刷新");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(70);
    connect(btnRefresh, &QPushButton::clicked, this, &ProcessInfoPage::refreshData);

    toolRow->addWidget(new QLabel("关键字："));
    toolRow->addWidget(m_edtKeyword);
    toolRow->addSpacing(8);
    toolRow->addWidget(new QLabel("风险："));
    toolRow->addWidget(m_cmbRisk);
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

    // DB字段: pid, name, path, user, cpu_pct, mem_mb, status, risk
    m_tbl = new QTableWidget(0, 8);
    m_tbl->setHorizontalHeaderLabels({"PID", "进程名", "路径", "CPU%", "内存(MB)", "用户", "状态", "风险"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_tbl->setColumnWidth(0, 60);
    m_tbl->setColumnWidth(3, 60);
    m_tbl->setColumnWidth(4, 80);
    m_mainLayout->addWidget(m_tbl, 1);
}

void ProcessInfoPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbRisk->setCurrentIndex(0);
    m_cmbStatus->setCurrentIndex(0);
    onQuery();
}

void ProcessInfoPage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     riskIdx = m_cmbRisk->currentIndex();
    int     stIdx   = m_cmbStatus->currentIndex();
    QStringList riskMap = {"", "高危", "中危", "低危"};
    QStringList stMap   = {"", "运行中", "已停止", "挂起"};
    QString risk   = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";
    QString status = (stIdx   > 0 && stIdx   < stMap.size())   ? stMap[stIdx]   : "";

    QString sql = "SELECT pid,name,path,user,cpu_pct,mem_mb,status,risk FROM process_info WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (name LIKE ? OR path LIKE ? OR user LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like;
    }
    if (!risk.isEmpty()) {
        sql += " AND risk = ?";
        binds << risk;
    }
    if (!status.isEmpty()) {
        sql += " AND status = ?";
        binds << status;
    }
    sql += " ORDER BY risk DESC, cpu_pct DESC";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}

void ProcessInfoPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["pid"].toString()));
        auto *nm = new QTableWidgetItem(m["name"].toString());
        QString risk = m["risk"].toString();
        if      (risk == "高危") nm->setForeground(QColor("#ef5350"));
        else if (risk == "中危") nm->setForeground(QColor("#ff9800"));
        m_tbl->setItem(r, 1, nm);
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["path"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(QString::number(m["cpu_pct"].toDouble(), 'f', 1)));
        m_tbl->setItem(r, 4, new QTableWidgetItem(QString::number(m["mem_mb"].toDouble(), 'f', 1)));
        m_tbl->setItem(r, 5, new QTableWidgetItem(m["user"].toString()));
        auto *st = new QTableWidgetItem(m["status"].toString());
        st->setForeground(m["status"].toString() == "运行中" ? QColor("#4caf50") : QColor("#90caf9"));
        st->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 6, st);
        auto *ri = new QTableWidgetItem(risk);
        if      (risk == "高危") ri->setForeground(QColor("#ef5350"));
        else if (risk == "中危") ri->setForeground(QColor("#ff9800"));
        else                     ri->setForeground(QColor("#4caf50"));
        ri->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 7, ri);
        if (risk == "高危")
            for (int c = 0; c < 8; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff1f0"));
    }
}
