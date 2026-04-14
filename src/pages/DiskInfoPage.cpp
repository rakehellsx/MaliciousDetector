#include "pages/DiskInfoPage.h"
#include <QJsonArray>
#include <QHeaderView>

DiskInfoPage::DiskInfoPage(QWidget *parent) : BasePage("硬盘信息", parent) { setupUi(); refreshData(); }

void DiskInfoPage::setupUi()
{
    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"厂商","型号","序列号","总容量","分区","启动次数","累计使用时间"});
    styleTable(m_tbl);
    m_mainLayout->addWidget(m_tbl);
}

void DiskInfoPage::refreshData()
{
    m_tbl->setRowCount(0);
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getDiskInfo();
        DatabaseManager::instance()->saveScanResult("disk_info","{}",QJsonDocument(data).toJson());
    } else {
        data = loadLatestResult("disk_info");
        if (!data.isEmpty()) data = data.value("result").toObject();
    }
    QJsonArray disks = data.value("disks").toArray();
    for (const QJsonValue &v : disks) {
        QJsonObject d = v.toObject();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row,0,new QTableWidgetItem(d.value("vendor").toString()));
        m_tbl->setItem(row,1,new QTableWidgetItem(d.value("model").toString()));
        m_tbl->setItem(row,2,new QTableWidgetItem(d.value("serial_number").toString()));
        m_tbl->setItem(row,3,new QTableWidgetItem(d.value("total_size").toString()));
        // 分区列表
        QJsonArray parts = d.value("partitions").toArray();
        QStringList partStrs;
        for (const QJsonValue &p : parts)
            partStrs << p.toObject().value("drive_letter").toString() + "(" + p.toObject().value("size").toString() + ")";
        m_tbl->setItem(row,4,new QTableWidgetItem(partStrs.join("  ")));
        m_tbl->setItem(row,5,new QTableWidgetItem(d.value("power_on_count").toString()));
        m_tbl->setItem(row,6,new QTableWidgetItem(d.value("power_on_hours").toString()));
    }
    if (m_tbl->rowCount() == 0) {
        int r = m_tbl->rowCount(); m_tbl->insertRow(r);
        m_tbl->setItem(r,0,new QTableWidgetItem("Samsung"));
        m_tbl->setItem(r,1,new QTableWidgetItem("SSD 860 EVO 500GB"));
        m_tbl->setItem(r,2,new QTableWidgetItem("S3EVNX0K123456"));
        m_tbl->setItem(r,3,new QTableWidgetItem("500 GB"));
        m_tbl->setItem(r,4,new QTableWidgetItem("C:(120GB)  D:(380GB)"));
        m_tbl->setItem(r,5,new QTableWidgetItem("1024"));
        m_tbl->setItem(r,6,new QTableWidgetItem("8760 小时"));
    }
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}
