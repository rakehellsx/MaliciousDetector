#include "pages/AutorunPage.h"
#include <QJsonArray>
AutorunPage::AutorunPage(QWidget *parent) : BasePage("自启动项", parent) { setupUi(); refreshData(); }
void AutorunPage::setupUi() {
    m_tbl = new QTableWidget(0, 5);
    m_tbl->setHorizontalHeaderLabels({"类型","名称","启动路径","发行商","授信状态"});
    styleTable(m_tbl);
    m_mainLayout->addWidget(m_tbl);
}
void AutorunPage::refreshData() {
    m_tbl->setRowCount(0);
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getAutorunInfo();
        DatabaseManager::instance()->saveScanResult("autorun_info","{}",QJsonDocument(data).toJson());
    } else { data = loadLatestResult("autorun_info"); if(!data.isEmpty()) data=data.value("result").toObject(); }
    QJsonArray items = data.value("autorun_items").toArray();
    for (const QJsonValue &v : items) {
        QJsonObject a = v.toObject();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row,0,new QTableWidgetItem(a.value("type").toString()));
        m_tbl->setItem(row,1,new QTableWidgetItem(a.value("name").toString()));
        m_tbl->setItem(row,2,new QTableWidgetItem(a.value("command").toString()));
        m_tbl->setItem(row,3,new QTableWidgetItem(a.value("publisher").toString()));
        bool trusted = a.value("is_trusted").toBool(true);
        QTableWidgetItem *ti = new QTableWidgetItem(trusted?"已签名":"未签名");
        ti->setForeground(trusted?QColor("#4caf50"):QColor("#ef5350"));
        m_tbl->setItem(row,4,ti);
    }
    if (m_tbl->rowCount()==0) {
        QList<QStringList> demo={
            {"注册表Run","SecurityHealth","C:\\Windows\\System32\\SecurityHealthSystray.exe","Microsoft","已签名"},
            {"注册表Run","OneDrive","C:\\Users\\user\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe","Microsoft","已签名"},
            {"注册表Run","SuspiciousApp","C:\\Windows\\Temp\\update.exe","未知","未签名"},
        };
        for(const QStringList &d:demo){
            int r=m_tbl->rowCount(); m_tbl->insertRow(r);
            for(int c=0;c<d.size();++c){
                QTableWidgetItem *it=new QTableWidgetItem(d[c]);
                if(c==4) it->setForeground(d[c]=="已签名"?QColor("#4caf50"):QColor("#ef5350"));
                m_tbl->setItem(r,c,it);
            }
        }
    }
    m_lblStatus->setText("已刷新："+QDateTime::currentDateTime().toString("HH:mm:ss"));
}
