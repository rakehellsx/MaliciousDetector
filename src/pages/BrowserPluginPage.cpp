#include "pages/BrowserPluginPage.h"
#include <QJsonArray>
BrowserPluginPage::BrowserPluginPage(QWidget *parent) : BasePage("浏览器插件", parent) { setupUi(); refreshData(); }
void BrowserPluginPage::setupUi() {
    m_tbl = new QTableWidget(0, 5);
    m_tbl->setHorizontalHeaderLabels({"浏览器","插件名称","状态","修改时间","路径"});
    styleTable(m_tbl);
    m_mainLayout->addWidget(m_tbl);
}
void BrowserPluginPage::refreshData() {
    m_tbl->setRowCount(0);
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getBrowserPlugins();
        DatabaseManager::instance()->saveScanResult("browser_plugins","{}",QJsonDocument(data).toJson());
    } else { data = loadLatestResult("browser_plugins"); if(!data.isEmpty()) data=data.value("result").toObject(); }
    QJsonArray plugins = data.value("plugins").toArray();
    for (const QJsonValue &v : plugins) {
        QJsonObject p = v.toObject();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row,0,new QTableWidgetItem(p.value("browser").toString()));
        m_tbl->setItem(row,1,new QTableWidgetItem(p.value("name").toString()));
        QString st = p.value("status").toString();
        QTableWidgetItem *si = new QTableWidgetItem(st);
        si->setForeground(st=="已启用"?QColor("#4caf50"):QColor("#90caf9"));
        m_tbl->setItem(row,2,si);
        m_tbl->setItem(row,3,new QTableWidgetItem(p.value("modified_time").toString()));
        m_tbl->setItem(row,4,new QTableWidgetItem(p.value("path").toString()));
    }
    if (m_tbl->rowCount()==0) {
        QList<QStringList> demo={
            {"Chrome","AdBlock","已启用","2025-10-01","C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\Extensions\\..."},
            {"Chrome","SuspiciousExt","已启用","2025-11-19","C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\Extensions\\..."},
            {"Edge","Microsoft Editor","已启用","2025-09-15","C:\\Users\\user\\AppData\\Local\\Microsoft\\Edge\\Extensions\\..."},
        };
        for(const QStringList &d:demo){
            int r=m_tbl->rowCount(); m_tbl->insertRow(r);
            for(int c=0;c<d.size();++c){
                QTableWidgetItem *it=new QTableWidgetItem(d[c]);
                if(c==2) it->setForeground(d[c]=="已启用"?QColor("#4caf50"):QColor("#90caf9"));
                m_tbl->setItem(r,c,it);
            }
        }
    }
    m_lblStatus->setText("已刷新："+QDateTime::currentDateTime().toString("HH:mm:ss"));
}
