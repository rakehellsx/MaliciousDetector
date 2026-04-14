#include "pages/ScheduledTaskPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

ScheduledTaskPage::ScheduledTaskPage(QWidget *parent)
    : BasePage("计划任务", parent)
{
    setupUi();
    refreshData();
}

void ScheduledTaskPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    toolRow->setSpacing(6);

    m_edtKeyword = new QLineEdit;
    m_edtKeyword->setPlaceholderText("任务名 / 执行命令 / 路径");
    m_edtKeyword->setClearButtonEnabled(true);
    m_edtKeyword->setFixedWidth(220);
    connect(m_edtKeyword, &QLineEdit::returnPressed, this, &ScheduledTaskPage::onQuery);

    m_cmbRisk = new QComboBox;
    m_cmbRisk->addItems({"全部风险", "高危", "中危", "低危"});
    connect(m_cmbRisk, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ScheduledTaskPage::onQuery);

    m_cmbStatus = new QComboBox;
    m_cmbStatus->addItems({"全部状态", "已启用", "已禁用"});
    connect(m_cmbStatus, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &ScheduledTaskPage::onQuery);

    QPushButton *btnQuery   = new QPushButton("查询");
    btnQuery->setObjectName("btnPrimary");
    btnQuery->setFixedWidth(70);
    connect(btnQuery, &QPushButton::clicked, this, &ScheduledTaskPage::onQuery);

    QPushButton *btnRefresh = new QPushButton("刷新");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(70);
    connect(btnRefresh, &QPushButton::clicked, this, &ScheduledTaskPage::refreshData);

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

    m_lblSummary = new QLabel;
    m_lblSummary->setObjectName("summaryLabel");
    m_mainLayout->addWidget(m_lblSummary);

    m_lblStatus = new QLabel;
    m_lblStatus->setObjectName("statusLabel");
    m_mainLayout->addWidget(m_lblStatus);

    // DB字段: name, path, trigger, action, status, last_run, risk
    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"任务名称", "触发方式", "执行命令", "路径", "状态", "上次运行", "风险"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl, 1);
}

void ScheduledTaskPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbRisk->setCurrentIndex(0);
    m_cmbStatus->setCurrentIndex(0);
    onQuery();
}

void ScheduledTaskPage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     riskIdx = m_cmbRisk->currentIndex();
    int     stIdx   = m_cmbStatus->currentIndex();
    QStringList riskMap = {"", "高危", "中危", "低危"};
    QStringList stMap   = {"", "已启用", "已禁用"};
    QString risk   = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";
    QString status = (stIdx   > 0 && stIdx   < stMap.size())   ? stMap[stIdx]   : "";

    QString sql = "SELECT name,trigger,action,path,status,last_run,risk FROM scheduled_task WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (name LIKE ? OR action LIKE ? OR path LIKE ?)";
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
    sql += " ORDER BY risk DESC, id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);

    int highRisk = 0;
    for (const QVariant &v : rows)
        if (v.toMap()["risk"].toString() == "高危") highRisk++;
    m_lblSummary->setText(QString("共 %1 个计划任务，其中高危 %2 个").arg(rows.size()).arg(highRisk));
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}

void ScheduledTaskPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["trigger"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["action"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["path"].toString()));
        m_tbl->setItem(r, 4, new QTableWidgetItem(m["status"].toString()));
        m_tbl->setItem(r, 5, new QTableWidgetItem(m["last_run"].toString()));
        QString risk = m["risk"].toString();
        auto *ri = new QTableWidgetItem(risk);
        if      (risk == "高危") ri->setForeground(QColor("#ef5350"));
        else if (risk == "中危") ri->setForeground(QColor("#ff9800"));
        else                     ri->setForeground(QColor("#4caf50"));
        ri->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 6, ri);
        if (risk == "高危")
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff1f0"));
    }
}
