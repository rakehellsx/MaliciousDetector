#include "pages/NetworkInfoPage.h"
#include <QJsonArray>
#include <QHeaderView>

NetworkInfoPage::NetworkInfoPage(QWidget *parent)
    : BasePage("网络信息", parent)
{ setupUi(); refreshData(); }

void NetworkInfoPage::setupUi()
{
    m_tbl = new QTableWidget(0, 6);
    m_tbl->setHorizontalHeaderLabels({"网卡名称","IP地址","子网掩码","默认网关","MAC地址","状态"});
    styleTable(m_tbl);
    m_tbl->setColumnWidth(0, 180);
    m_tbl->setColumnWidth(1, 130);
    m_tbl->setColumnWidth(2, 130);
    m_tbl->setColumnWidth(3, 130);
    m_tbl->setColumnWidth(4, 140);
    m_mainLayout->addWidget(m_tbl);
}

void NetworkInfoPage::refreshData()
{
    m_tbl->setRowCount(0);
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getNetworkInfo();
        DatabaseManager::instance()->saveScanResult("network_info", "{}", QJsonDocument(data).toJson());
    } else {
        data = loadLatestResult("network_info");
        if (!data.isEmpty()) data = data.value("result").toObject();
    }

    QJsonArray adapters = data.value("adapters").toArray();
    for (const QJsonValue &v : adapters) {
        QJsonObject a = v.toObject();
        // 每个网卡可能有多个IP
        QJsonArray ips = a.value("ip_addresses").toArray();
        if (ips.isEmpty()) {
            int row = m_tbl->rowCount(); m_tbl->insertRow(row);
            m_tbl->setItem(row,0,new QTableWidgetItem(a.value("name").toString()));
            m_tbl->setItem(row,1,new QTableWidgetItem("--"));
            m_tbl->setItem(row,2,new QTableWidgetItem("--"));
            m_tbl->setItem(row,3,new QTableWidgetItem(a.value("gateway").toString()));
            m_tbl->setItem(row,4,new QTableWidgetItem(a.value("mac").toString()));
            m_tbl->setItem(row,5,new QTableWidgetItem(a.value("status").toString()));
        } else {
            for (const QJsonValue &ipv : ips) {
                QJsonObject ip = ipv.toObject();
                int row = m_tbl->rowCount(); m_tbl->insertRow(row);
                m_tbl->setItem(row,0,new QTableWidgetItem(a.value("name").toString()));
                m_tbl->setItem(row,1,new QTableWidgetItem(ip.value("address").toString()));
                m_tbl->setItem(row,2,new QTableWidgetItem(ip.value("subnet_mask").toString()));
                m_tbl->setItem(row,3,new QTableWidgetItem(a.value("gateway").toString()));
                m_tbl->setItem(row,4,new QTableWidgetItem(a.value("mac").toString()));
                m_tbl->setItem(row,5,new QTableWidgetItem(a.value("status").toString("已连接")));
            }
        }
    }
    if (m_tbl->rowCount() == 0) {
        // 示例数据
        auto addRow = [&](const QString &name, const QString &ip, const QString &mask,
                          const QString &gw, const QString &mac, const QString &st) {
            int r = m_tbl->rowCount(); m_tbl->insertRow(r);
            m_tbl->setItem(r,0,new QTableWidgetItem(name));
            m_tbl->setItem(r,1,new QTableWidgetItem(ip));
            m_tbl->setItem(r,2,new QTableWidgetItem(mask));
            m_tbl->setItem(r,3,new QTableWidgetItem(gw));
            m_tbl->setItem(r,4,new QTableWidgetItem(mac));
            QTableWidgetItem *si = new QTableWidgetItem(st);
            si->setForeground(st == "已连接" ? QColor("#4caf50") : QColor("#ef5350"));
            m_tbl->setItem(r,5,si);
        };
        addRow("以太网","192.168.1.100","255.255.255.0","192.168.1.1","00:1A:2B:3C:4D:5E","已连接");
        addRow("本地回环","127.0.0.1","255.0.0.0","--","--","已连接");
    }
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}
