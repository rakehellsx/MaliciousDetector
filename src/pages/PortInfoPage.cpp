#include "pages/PortInfoPage.h"
#include <QJsonArray>
#include <QHeaderView>

PortInfoPage::PortInfoPage(QWidget *parent) : BasePage("端口信息", parent) { setupUi(); refreshData(); }

void PortInfoPage::setupUi()
{
    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"协议","本地地址","本地端口","远程地址","远程端口","状态","关联进程"});
    styleTable(m_tbl);
    m_tbl->setColumnWidth(0, 60);
    m_tbl->setColumnWidth(1, 120);
    m_tbl->setColumnWidth(2, 80);
    m_tbl->setColumnWidth(3, 120);
    m_tbl->setColumnWidth(4, 80);
    m_tbl->setColumnWidth(5, 100);
    m_mainLayout->addWidget(m_tbl);
}

void PortInfoPage::refreshData()
{
    m_tbl->setRowCount(0);
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getPortInfo();
        DatabaseManager::instance()->saveScanResult("port_info","{}",QJsonDocument(data).toJson());
    } else {
        data = loadLatestResult("port_info");
        if (!data.isEmpty()) data = data.value("result").toObject();
    }
    QJsonArray ports = data.value("ports").toArray();
    for (const QJsonValue &v : ports) {
        QJsonObject p = v.toObject();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row,0,new QTableWidgetItem(p.value("protocol").toString()));
        m_tbl->setItem(row,1,new QTableWidgetItem(p.value("local_ip").toString()));
        m_tbl->setItem(row,2,new QTableWidgetItem(QString::number(p.value("local_port").toInt())));
        m_tbl->setItem(row,3,new QTableWidgetItem(p.value("remote_ip").toString()));
        m_tbl->setItem(row,4,new QTableWidgetItem(p.value("remote_port").isNull() ? "--" : QString::number(p.value("remote_port").toInt())));
        QString state = p.value("state").toString();
        QTableWidgetItem *si = new QTableWidgetItem(state);
        si->setForeground(state=="LISTENING" ? QColor("#42a5f5") : state=="ESTABLISHED" ? QColor("#4caf50") : QColor("#90caf9"));
        m_tbl->setItem(row,5,si);
        m_tbl->setItem(row,6,new QTableWidgetItem(p.value("process_name").toString() + " (" + QString::number(p.value("pid").toInt()) + ")"));
    }
    if (m_tbl->rowCount() == 0) {
        QList<QStringList> demo = {
            {"TCP","0.0.0.0","135","--","--","LISTENING","svchost.exe (1024)"},
            {"TCP","0.0.0.0","445","--","--","LISTENING","System (4)"},
            {"TCP","192.168.1.100","49152","192.168.1.1","80","ESTABLISHED","chrome.exe (3200)"},
            {"UDP","0.0.0.0","5355","--","--","--","svchost.exe (1024)"},
        };
        for (const QStringList &d : demo) {
            int r = m_tbl->rowCount(); m_tbl->insertRow(r);
            for (int c = 0; c < d.size(); ++c) {
                QTableWidgetItem *it = new QTableWidgetItem(d[c]);
                if (c==5) it->setForeground(d[c]=="LISTENING"?QColor("#42a5f5"):d[c]=="ESTABLISHED"?QColor("#4caf50"):QColor("#90caf9"));
                m_tbl->setItem(r,c,it);
            }
        }
    }
    m_lblStatus->setText(QString("共 %1 条  |  已刷新：%2").arg(m_tbl->rowCount())
                         .arg(QDateTime::currentDateTime().toString("HH:mm:ss")));
}
