#include "pages/PortInfoPage.h"
#include "ui_PortInfoPage.h"

#include "DatabaseManager.h"
#include <QTableWidgetItem>
#include <QPushButton>
#include <QColor>
#include <QHeaderView>

PortInfoPage::PortInfoPage(QWidget *parent)
    : BasePage("端口监听", parent)
{
    ui = new Ui::PortInfoPage();
    ui->setupUi(this);
    postSetupUi();

    m_tbl        = ui->m_tbl;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbProto   = ui->m_cmbProto;
    m_cmbRisk    = ui->m_cmbRisk;
    m_lblStatus  = ui->m_lblStatus;

    m_tbl->horizontalHeader()->setStretchLastSection(true);
    m_tbl->verticalHeader()->setVisible(false);

    connect(ui->btnQuery,   &QPushButton::clicked, this, &PortInfoPage::onQuery);
    connect(ui->btnRefresh, &QPushButton::clicked, this, &PortInfoPage::refreshData);
    connect(ui->btnExport,  &QPushButton::clicked, this, [this]{ m_lblStatus->setText("导出功能开发中..."); });

    refreshData();
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
    QStringList riskMap = {"", "高危", "中危", "低危", "正常"};
    QString risk  = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";

    auto rows = DatabaseManager::instance()->execSelect(
        "SELECT protocol,local_ip,local_port,remote_ip,remote_port,state,process_name,pid,risk"
        " FROM port_info WHERE 1=1 ORDER BY risk DESC, id", {});

    if (rows.isEmpty()) {
        loadDemoData();
        return;
    }

    QVariantList filtered;
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        if (!kw.isEmpty()) {
            bool match = m["local_ip"].toString().contains(kw, Qt::CaseInsensitive)
                      || m["local_port"].toString().contains(kw, Qt::CaseInsensitive)
                      || m["remote_ip"].toString().contains(kw, Qt::CaseInsensitive)
                      || m["process_name"].toString().contains(kw, Qt::CaseInsensitive);
            if (!match) continue;
        }
        if (!proto.isEmpty() && m["protocol"].toString() != proto) continue;
        if (!risk.isEmpty()  && m["risk"].toString()     != risk)  continue;
        filtered << v;
    }
    fillTable(filtered);
}

void PortInfoPage::loadDemoData()
{
    // 演示数据与原型一致（9列：协议/本地地址/本地端口/远程地址/远程端口/状态/进程/PID/风险）
    struct PortRow {
        QString proto, localIp, localPort, remoteIp, remotePort, state, proc, pid, risk;
    };
    QList<PortRow> demo = {
        {"TCP", "0.0.0.0",       "445",  "—",              "—",    "LISTEN",      "System",         "4",    "正常"},
        {"TCP", "0.0.0.0",       "3389", "—",              "—",    "LISTEN",      "svchost.exe",    "892",  "中危"},
        {"TCP", "192.168.1.100", "49721","185.220.101.45", "4444", "ESTABLISHED", "svchost32.exe",  "5671", "高危"},
        {"TCP", "192.168.1.100", "49823","192.168.1.1",    "80",   "ESTABLISHED", "chrome.exe",     "4892", "正常"},
        {"UDP", "0.0.0.0",       "5355", "—",              "—",    "—",           "svchost.exe",    "892",  "正常"},
        {"TCP", "127.0.0.1",     "27017","—",              "—",    "LISTEN",      "mongod.exe",     "3210", "正常"},
        {"TCP", "0.0.0.0",       "1433", "—",              "—",    "LISTEN",      "sqlservr.exe",   "2890", "中危"},
    };

    m_tbl->setRowCount(0);
    for (const auto &d : demo) {
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);

        auto *pi = new QTableWidgetItem(d.proto);
        pi->setTextAlignment(Qt::AlignCenter);
        pi->setForeground(d.proto == "TCP" ? QColor("#3182ce") : QColor("#805ad5"));
        m_tbl->setItem(r, 0, pi);

        m_tbl->setItem(r, 1, new QTableWidgetItem(d.localIp));

        auto *lp = new QTableWidgetItem(d.localPort);
        lp->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 2, lp);

        auto *ri = new QTableWidgetItem(d.remoteIp);
        if (d.remoteIp.startsWith("185.")) ri->setForeground(QColor("#e53e3e"));
        m_tbl->setItem(r, 3, ri);

        auto *rp = new QTableWidgetItem(d.remotePort);
        rp->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 4, rp);

        auto *si = new QTableWidgetItem(d.state);
        si->setTextAlignment(Qt::AlignCenter);
        if      (d.state == "LISTEN")      si->setForeground(QColor("#38a169"));
        else if (d.state == "ESTABLISHED") si->setForeground(QColor("#3182ce"));
        else if (d.state == "TIME_WAIT")   si->setForeground(QColor("#dd6b20"));
        m_tbl->setItem(r, 5, si);

        m_tbl->setItem(r, 6, new QTableWidgetItem(d.proc));

        auto *pidItem = new QTableWidgetItem(d.pid);
        pidItem->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 7, pidItem);

        auto *rk = new QTableWidgetItem(d.risk);
        rk->setTextAlignment(Qt::AlignCenter);
        if      (d.risk == "高危") { rk->setForeground(QColor("#e53e3e")); }
        else if (d.risk == "中危") { rk->setForeground(QColor("#dd6b20")); }
        else                       { rk->setForeground(QColor("#38a169")); }
        m_tbl->setItem(r, 8, rk);

        if (d.risk == "高危")
            for (int c = 0; c < 9; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff5f5"));
    }
    m_lblStatus->setText(QString("共 %1 条记录").arg(demo.size()));
}

void PortInfoPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);

        auto *pi = new QTableWidgetItem(m["protocol"].toString());
        pi->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 0, pi);
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["local_ip"].toString()));
        auto *lp = new QTableWidgetItem(m["local_port"].toString());
        lp->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 2, lp);
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["remote_ip"].toString()));
        auto *rp = new QTableWidgetItem(m["remote_port"].toString());
        rp->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 4, rp);
        QString state = m["state"].toString();
        auto *si = new QTableWidgetItem(state);
        si->setTextAlignment(Qt::AlignCenter);
        if      (state == "LISTEN")      si->setForeground(QColor("#38a169"));
        else if (state == "ESTABLISHED") si->setForeground(QColor("#3182ce"));
        else if (state == "TIME_WAIT")   si->setForeground(QColor("#dd6b20"));
        m_tbl->setItem(r, 5, si);
        m_tbl->setItem(r, 6, new QTableWidgetItem(m["process_name"].toString()));
        auto *pidItem = new QTableWidgetItem(m["pid"].toString());
        pidItem->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 7, pidItem);
        QString risk = m["risk"].toString();
        auto *rk = new QTableWidgetItem(risk);
        rk->setTextAlignment(Qt::AlignCenter);
        if      (risk == "高危") rk->setForeground(QColor("#e53e3e"));
        else if (risk == "中危") rk->setForeground(QColor("#dd6b20"));
        else                     rk->setForeground(QColor("#38a169"));
        m_tbl->setItem(r, 8, rk);
        if (risk == "高危")
            for (int c = 0; c < 9; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff5f5"));
    }
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}
