#include "pages/PortInfoPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>

PortInfoPage::PortInfoPage(QWidget *parent)
    : BasePage("端口信息", parent)
{
    setupUi();
    refreshData();
}

void PortInfoPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    toolRow->setSpacing(6);

    m_edtKeyword = new QLineEdit;
    m_edtKeyword->setPlaceholderText("本地IP / 端口 / 远程地址 / 进程名");
    m_edtKeyword->setClearButtonEnabled(true);
    m_edtKeyword->setFixedWidth(240);
    connect(m_edtKeyword, &QLineEdit::returnPressed, this, &PortInfoPage::onQuery);

    m_cmbProto = new QComboBox;
    m_cmbProto->addItems({"全部协议", "TCP", "UDP"});
    connect(m_cmbProto, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PortInfoPage::onQuery);

    m_cmbRisk = new QComboBox;
    m_cmbRisk->addItems({"全部风险", "高危", "中危", "低危"});
    connect(m_cmbRisk, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PortInfoPage::onQuery);

    QPushButton *btnQuery   = new QPushButton("查询");
    btnQuery->setObjectName("btnPrimary");
    btnQuery->setFixedWidth(70);
    connect(btnQuery, &QPushButton::clicked, this, &PortInfoPage::onQuery);

    QPushButton *btnRefresh = new QPushButton("刷新");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(70);
    connect(btnRefresh, &QPushButton::clicked, this, &PortInfoPage::refreshData);

    toolRow->addWidget(new QLabel("关键字："));
    toolRow->addWidget(m_edtKeyword);
    toolRow->addSpacing(8);
    toolRow->addWidget(new QLabel("协议："));
    toolRow->addWidget(m_cmbProto);
    toolRow->addSpacing(8);
    toolRow->addWidget(new QLabel("风险："));
    toolRow->addWidget(m_cmbRisk);
    toolRow->addWidget(btnQuery);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    m_lblStatus = new QLabel;
    m_lblStatus->setObjectName("statusLabel");
    m_mainLayout->addWidget(m_lblStatus);

    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"协议", "本地IP", "本地端口", "远程地址:端口", "状态", "进程", "风险"});
    styleTable(m_tbl);
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_mainLayout->addWidget(m_tbl, 1);
}

void PortInfoPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbProto->setCurrentIndex(0);
    m_cmbRisk->setCurrentIndex(0);
    onQuery();
}

void PortInfoPage::onQuery()
{
    QString kw    = m_edtKeyword->text().trimmed();
    int protoIdx  = m_cmbProto->currentIndex();
    int riskIdx   = m_cmbRisk->currentIndex();
    QString proto = protoIdx == 1 ? "TCP" : protoIdx == 2 ? "UDP" : "";
    QStringList riskMap = {"", "高危", "中危", "低危"};
    QString risk  = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";

    QString sql = "SELECT protocol,local_ip,local_port,remote_ip,remote_port,state,process_name,pid,risk"
                  " FROM port_info WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (local_ip LIKE ? OR local_port LIKE ? OR remote_ip LIKE ?"
               " OR remote_port LIKE ? OR process_name LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like << like << like;
    }
    if (!proto.isEmpty()) {
        sql += " AND protocol = ?";
        binds << proto;
    }
    if (!risk.isEmpty()) {
        sql += " AND risk = ?";
        binds << risk;
    }
    sql += " ORDER BY risk DESC, id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}

void PortInfoPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["protocol"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["local_ip"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["local_port"].toString()));
        QString remoteAddr = m["remote_ip"].toString();
        if (!m["remote_port"].toString().isEmpty() && m["remote_port"].toString() != "0")
            remoteAddr += ":" + m["remote_port"].toString();
        m_tbl->setItem(r, 3, new QTableWidgetItem(remoteAddr));
        QString state = m["state"].toString();
        auto *st = new QTableWidgetItem(state);
        if      (state == "LISTEN")      st->setForeground(QColor("#4caf50"));
        else if (state == "ESTABLISHED") st->setForeground(QColor("#42a5f5"));
        else if (state == "TIME_WAIT")   st->setForeground(QColor("#ff9800"));
        st->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 4, st);
        m_tbl->setItem(r, 5, new QTableWidgetItem(m["process_name"].toString()));
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
