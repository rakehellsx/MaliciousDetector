#include "pages/NetworkInfoPage.h"
#include "ui_NetworkInfoPage.h"

#include "DatabaseManager.h"
#include <QTableWidgetItem>
#include <QColor>

NetworkInfoPage::NetworkInfoPage(QWidget *parent)
    : BasePage("网络连接", parent)
{
    ui = new Ui::NetworkInfoPage();
    ui->setupUi(this);
    postSetupUi();

    m_tblNic   = ui->m_tblNic;
    m_tblDns   = ui->m_tblDns;
    m_tblRoute = ui->m_tblRoute;
    m_lblStatus = ui->m_lblStatus;

    // 表格通用设置
    for (auto *tbl : {m_tblNic, m_tblDns, m_tblRoute}) {
        tbl->horizontalHeader()->setStretchLastSection(true);
        tbl->verticalHeader()->setVisible(false);
        tbl->setShowGrid(true);
    }

    connect(ui->btnRefresh, &QPushButton::clicked, this, &NetworkInfoPage::refreshData);
    connect(ui->btnExport,  &QPushButton::clicked, this, [this]{ m_lblStatus->setText("导出功能开发中..."); });

    refreshData();
}

void NetworkInfoPage::refreshData()
{
    loadNicData();
    loadDnsData();
    loadRouteData();
    m_lblStatus->setText("数据已刷新");
}

// ─── 网卡与IP配置 ─────────────────────────────────────────────────────────────
void NetworkInfoPage::loadNicData()
{
    // 尝试从数据库读取，失败则用演示数据
    auto rows = DatabaseManager::instance()->execSelect(
        "SELECT name,ip,mask,gateway,mac,status FROM net_info ORDER BY id", {});

    if (rows.isEmpty()) {
        // 演示数据（与原型一致）
        struct NicRow { QString name, ip, mask, gateway, mac, status; };
        QList<NicRow> demo = {
            {"以太网 (Intel I219-V)",     "192.168.1.100", "255.255.255.0", "192.168.1.1", "00:1A:2B:3C:4D:5E", "已连接"},
            {"无线局域网 (Intel AX201)",  "10.0.0.105",    "255.255.255.0", "10.0.0.1",   "A4:C3:F0:12:34:56", "已断开"},
            {"Loopback",                  "127.0.0.1",     "255.0.0.0",     "—",           "—",                 "已连接"},
        };
        m_tblNic->setRowCount(0);
        for (const auto &d : demo) {
            int r = m_tblNic->rowCount();
            m_tblNic->insertRow(r);
            m_tblNic->setItem(r, 0, new QTableWidgetItem(d.name));
            m_tblNic->setItem(r, 1, new QTableWidgetItem(d.ip));
            m_tblNic->setItem(r, 2, new QTableWidgetItem(d.mask));
            m_tblNic->setItem(r, 3, new QTableWidgetItem(d.gateway));
            m_tblNic->setItem(r, 4, new QTableWidgetItem(d.mac));
            auto *si = new QTableWidgetItem(d.status);
            si->setForeground(d.status == "已连接" ? QColor("#38a169") : QColor("#718096"));
            si->setTextAlignment(Qt::AlignCenter);
            m_tblNic->setItem(r, 5, si);
        }
        return;
    }

    m_tblNic->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tblNic->rowCount();
        m_tblNic->insertRow(r);
        m_tblNic->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        m_tblNic->setItem(r, 1, new QTableWidgetItem(m["ip"].toString()));
        m_tblNic->setItem(r, 2, new QTableWidgetItem(m["mask"].toString()));
        m_tblNic->setItem(r, 3, new QTableWidgetItem(m["gateway"].toString()));
        m_tblNic->setItem(r, 4, new QTableWidgetItem(m["mac"].toString()));
        QString st = m["status"].toString();
        auto *si = new QTableWidgetItem(st);
        si->setForeground(st == "已连接" ? QColor("#38a169") : QColor("#718096"));
        si->setTextAlignment(Qt::AlignCenter);
        m_tblNic->setItem(r, 5, si);
    }
}

// ─── DNS配置 ─────────────────────────────────────────────────────────────────
void NetworkInfoPage::loadDnsData()
{
    m_tblDns->setRowCount(0);

    struct DnsRow { QString key, val; };
    QList<DnsRow> demo = {
        {"首选DNS",  "192.168.1.1"},
        {"备用DNS",  "8.8.8.8"},
        {"Hosts文件","未篡改  C:\\Windows\\System32\\drivers\\etc\\hosts"},
    };
    for (const auto &d : demo) {
        int r = m_tblDns->rowCount();
        m_tblDns->insertRow(r);
        auto *ki = new QTableWidgetItem(d.key);
        ki->setForeground(QColor("#2c5282"));
        ki->setFont(QFont("", -1, QFont::Medium));
        m_tblDns->setItem(r, 0, ki);
        m_tblDns->setItem(r, 1, new QTableWidgetItem(d.val));
    }
}

// ─── 路由表 ───────────────────────────────────────────────────────────────────
void NetworkInfoPage::loadRouteData()
{
    m_tblRoute->setRowCount(0);

    struct RouteRow { QString dest, mask, gw, iface, metric; };
    QList<RouteRow> demo = {
        {"0.0.0.0",       "0.0.0.0",       "192.168.1.1", "192.168.1.100", "25"},
        {"192.168.1.0",   "255.255.255.0",  "在链路上",    "192.168.1.100", "281"},
        {"127.0.0.0",     "255.0.0.0",      "在链路上",    "127.0.0.1",     "331"},
    };
    for (const auto &d : demo) {
        int r = m_tblRoute->rowCount();
        m_tblRoute->insertRow(r);
        m_tblRoute->setItem(r, 0, new QTableWidgetItem(d.dest));
        m_tblRoute->setItem(r, 1, new QTableWidgetItem(d.mask));
        m_tblRoute->setItem(r, 2, new QTableWidgetItem(d.gw));
        m_tblRoute->setItem(r, 3, new QTableWidgetItem(d.iface));
        auto *mi = new QTableWidgetItem(d.metric);
        mi->setTextAlignment(Qt::AlignCenter);
        m_tblRoute->setItem(r, 4, mi);
    }
}
