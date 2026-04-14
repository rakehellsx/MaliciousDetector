#include "pages/SharedResourcePage.h"
#include <QJsonArray>
SharedResourcePage::SharedResourcePage(QWidget *parent) : BasePage("共享资源", parent) { setupUi(); refreshData(); }
void SharedResourcePage::setupUi() {
    m_tbl = new QTableWidget(0, 4);
    m_tbl->setHorizontalHeaderLabels({"共享名称","资源类型","当前访问用户","映像路径"});
    styleTable(m_tbl);
    m_mainLayout->addWidget(m_tbl);
}
void SharedResourcePage::refreshData() {
    m_tbl->setRowCount(0);
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getSharedResources();
        DatabaseManager::instance()->saveScanResult("shared_resources","{}",QJsonDocument(data).toJson());
    } else { data = loadLatestResult("shared_resources"); if(!data.isEmpty()) data=data.value("result").toObject(); }
    QJsonArray shares = data.value("shares").toArray();
    for (const QJsonValue &v : shares) {
        QJsonObject s = v.toObject();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row,0,new QTableWidgetItem(s.value("name").toString()));
        m_tbl->setItem(row,1,new QTableWidgetItem(s.value("type").toString()));
        m_tbl->setItem(row,2,new QTableWidgetItem(s.value("current_users").toString()));
        m_tbl->setItem(row,3,new QTableWidgetItem(s.value("path").toString()));
    }
    if (m_tbl->rowCount()==0) {
        QList<QStringList> demo={{"ADMIN$","磁盘","0","C:\\Windows"},{"C$","磁盘","0","C:\\"},{"IPC$","IPC","0","--"}};
        for(const QStringList &d:demo){
            int r=m_tbl->rowCount(); m_tbl->insertRow(r);
            for(int c=0;c<d.size();++c) m_tbl->setItem(r,c,new QTableWidgetItem(d[c]));
        }
    }
    m_lblStatus->setText("已刷新："+QDateTime::currentDateTime().toString("HH:mm:ss"));
}
