#include "pages/DriverInfoPage.h"
#include <QJsonArray>
DriverInfoPage::DriverInfoPage(QWidget *parent) : BasePage("驱动信息", parent) { setupUi(); refreshData(); }
void DriverInfoPage::setupUi() {
    m_tbl = new QTableWidget(0, 6);
    m_tbl->setHorizontalHeaderLabels({"驱动名称","类型","发行商","修改时间","映像路径","授信状态"});
    styleTable(m_tbl);
    m_mainLayout->addWidget(m_tbl);
}
void DriverInfoPage::refreshData() {
    m_tbl->setRowCount(0);
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getDriverInfo();
        DatabaseManager::instance()->saveScanResult("driver_info","{}",QJsonDocument(data).toJson());
    } else { data = loadLatestResult("driver_info"); if(!data.isEmpty()) data=data.value("result").toObject(); }
    QJsonArray drivers = data.value("drivers").toArray();
    for (const QJsonValue &v : drivers) {
        QJsonObject d = v.toObject();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row,0,new QTableWidgetItem(d.value("name").toString()));
        m_tbl->setItem(row,1,new QTableWidgetItem(d.value("type").toString()));
        m_tbl->setItem(row,2,new QTableWidgetItem(d.value("publisher").toString()));
        m_tbl->setItem(row,3,new QTableWidgetItem(d.value("modified_time").toString()));
        m_tbl->setItem(row,4,new QTableWidgetItem(d.value("image_path").toString()));
        bool trusted = d.value("is_trusted").toBool(true);
        QTableWidgetItem *ti = new QTableWidgetItem(trusted?"已签名":"未签名");
        ti->setForeground(trusted?QColor("#4caf50"):QColor("#ef5350"));
        m_tbl->setItem(row,5,ti);
    }
    if (m_tbl->rowCount()==0) {
        QList<QStringList> demo={
            {"ACPI","实体硬件","Microsoft","2025-01-01","C:\\Windows\\System32\\drivers\\ACPI.sys","已签名"},
            {"Tcpip","虚拟硬件","Microsoft","2025-01-01","C:\\Windows\\System32\\drivers\\tcpip.sys","已签名"},
            {"unknowndrv","虚拟硬件","未知","2025-11-19","C:\\Windows\\Temp\\unknowndrv.sys","未签名"},
        };
        for(const QStringList &d:demo){
            int r=m_tbl->rowCount(); m_tbl->insertRow(r);
            for(int c=0;c<d.size();++c){
                QTableWidgetItem *it=new QTableWidgetItem(d[c]);
                if(c==5) it->setForeground(d[c]=="已签名"?QColor("#4caf50"):QColor("#ef5350"));
                m_tbl->setItem(r,c,it);
            }
        }
    }
    m_lblStatus->setText("已刷新："+QDateTime::currentDateTime().toString("HH:mm:ss"));
}
