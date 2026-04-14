#include "pages/MemoryImagePage.h"
#include <QJsonArray>
#include <QHBoxLayout>
#include <QPushButton>
MemoryImagePage::MemoryImagePage(QWidget *parent) : BasePage("内存映像", parent) { setupUi(); refreshData(); }
void MemoryImagePage::setupUi() {
    m_tbl = new QTableWidget(0, 6);
    m_tbl->setHorizontalHeaderLabels({"模块名称","基址","映像大小","序号","映像路径","授信状态"});
    styleTable(m_tbl);
    m_mainLayout->addWidget(m_tbl);
}
void MemoryImagePage::refreshData() {
    m_tbl->setRowCount(0);
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getMemoryImageInfo();
        DatabaseManager::instance()->saveScanResult("memory_image","{}",QJsonDocument(data).toJson());
    } else { data = loadLatestResult("memory_image"); if(!data.isEmpty()) data=data.value("result").toObject(); }
    QJsonArray modules = data.value("kernel_modules").toArray();
    for (const QJsonValue &v : modules) {
        QJsonObject m = v.toObject();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row,0,new QTableWidgetItem(m.value("name").toString()));
        m_tbl->setItem(row,1,new QTableWidgetItem(m.value("base_address").toString()));
        m_tbl->setItem(row,2,new QTableWidgetItem(m.value("image_size").toString()));
        m_tbl->setItem(row,3,new QTableWidgetItem(QString::number(m.value("index").toInt())));
        m_tbl->setItem(row,4,new QTableWidgetItem(m.value("path").toString()));
        bool trusted = m.value("is_trusted").toBool(true);
        QTableWidgetItem *ti = new QTableWidgetItem(trusted?"已签名":"未签名");
        ti->setForeground(trusted?QColor("#4caf50"):QColor("#ef5350"));
        m_tbl->setItem(row,5,ti);
    }
    if (m_tbl->rowCount()==0) {
        QList<QStringList> demo={
            {"ntoskrnl.exe","0xFFFFF80000000000","0x800000","0","C:\\Windows\\System32\\ntoskrnl.exe","已签名"},
            {"hal.dll","0xFFFFF80001000000","0x80000","1","C:\\Windows\\System32\\hal.dll","已签名"},
            {"unknownmod.sys","0xFFFFF80002000000","0x10000","--","C:\\Windows\\Temp\\unknownmod.sys","未签名"},
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
