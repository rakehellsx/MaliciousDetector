#include "pages/ProcessInfoPage.h"
#include <QJsonArray>
#include <QHeaderView>
#include <QLineEdit>
#include <QHBoxLayout>

ProcessInfoPage::ProcessInfoPage(QWidget *parent) : BasePage("进程信息", parent) { setupUi(); refreshData(); }

void ProcessInfoPage::setupUi()
{
    // 搜索栏
    QHBoxLayout *searchRow = new QHBoxLayout;
    QLineEdit *editSearch = new QLineEdit;
    editSearch->setPlaceholderText("搜索进程名称...");
    editSearch->setObjectName("searchInput");
    searchRow->addWidget(editSearch);
    searchRow->addStretch();
    m_mainLayout->addLayout(searchRow);

    m_tbl = new QTableWidget(0, 7);
    m_tbl->setHorizontalHeaderLabels({"PID","进程名称","映像路径","发行商","线程数","内存(KB)","授信状态"});
    styleTable(m_tbl);
    m_tbl->setColumnWidth(0, 60);
    m_tbl->setColumnWidth(1, 140);
    m_tbl->setColumnWidth(3, 160);
    m_tbl->setColumnWidth(4, 60);
    m_tbl->setColumnWidth(5, 80);
    m_mainLayout->addWidget(m_tbl);
}

void ProcessInfoPage::refreshData()
{
    m_tbl->setRowCount(0);
    QJsonObject data;
    if (m_loader && m_loader->isLoaded()) {
        data = m_loader->getProcessInfo();
        DatabaseManager::instance()->saveScanResult("process_info","{}",QJsonDocument(data).toJson());
    } else {
        data = loadLatestResult("process_info");
        if (!data.isEmpty()) data = data.value("result").toObject();
    }
    QJsonArray procs = data.value("processes").toArray();
    for (const QJsonValue &v : procs) {
        QJsonObject p = v.toObject();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row,0,new QTableWidgetItem(QString::number(p.value("pid").toInt())));
        m_tbl->setItem(row,1,new QTableWidgetItem(p.value("name").toString()));
        m_tbl->setItem(row,2,new QTableWidgetItem(p.value("image_path").toString()));
        m_tbl->setItem(row,3,new QTableWidgetItem(p.value("publisher").toString()));
        m_tbl->setItem(row,4,new QTableWidgetItem(QString::number(p.value("thread_count").toInt())));
        m_tbl->setItem(row,5,new QTableWidgetItem(QString::number(p.value("memory_kb").toInt())));
        bool trusted = p.value("is_trusted").toBool(true);
        QTableWidgetItem *ti = new QTableWidgetItem(trusted ? "已签名" : "未签名");
        ti->setForeground(trusted ? QColor("#4caf50") : QColor("#ef5350"));
        m_tbl->setItem(row,6,ti);
    }
    if (m_tbl->rowCount() == 0) {
        // 示例数据
        QList<QStringList> demo = {
            {"4","System","--","Microsoft Corporation","--","--","已签名"},
            {"1024","svchost.exe","C:\\Windows\\System32\\svchost.exe","Microsoft Corporation","12","8192","已签名"},
            {"2048","explorer.exe","C:\\Windows\\explorer.exe","Microsoft Corporation","32","45000","已签名"},
            {"9012","svchost32.exe","C:\\Windows\\Temp\\svchost32.exe","未知","2","4096","未签名"},
        };
        for (const QStringList &d : demo) {
            int r = m_tbl->rowCount(); m_tbl->insertRow(r);
            for (int c = 0; c < d.size(); ++c) {
                QTableWidgetItem *it = new QTableWidgetItem(d[c]);
                if (c == 6) it->setForeground(d[c]=="已签名" ? QColor("#4caf50") : QColor("#ef5350"));
                m_tbl->setItem(r,c,it);
            }
        }
    }
    m_lblStatus->setText(QString("共 %1 个进程  |  已刷新：%2").arg(m_tbl->rowCount())
                         .arg(QDateTime::currentDateTime().toString("HH:mm:ss")));
}
