#include "pages/FileAssocPage.h"
#include <QHBoxLayout>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QHeaderView>

FileAssocPage::FileAssocPage(QWidget *parent) : BasePage("文件关联检测", parent) { setupUi(); refreshData(); }

void FileAssocPage::setupUi()
{
    QHBoxLayout *btnRow = new QHBoxLayout;
    m_btnScan = new QPushButton("扫描文件关联");
    m_btnScan->setObjectName("btnPrimary");
    m_btnScan->setFixedWidth(120);
    connect(m_btnScan, &QPushButton::clicked, this, &FileAssocPage::refreshData);
    btnRow->addWidget(m_btnScan);
    btnRow->addStretch();
    m_mainLayout->addLayout(btnRow);

    m_tbl = new QTableWidget(0, 5);
    m_tbl->setHorizontalHeaderLabels({"扩展名","关联程序","正常值","当前值","风险"});
    styleTable(m_tbl);
    m_tbl->setColumnWidth(0, 80);
    m_tbl->setColumnWidth(1, 160);
    m_tbl->setColumnWidth(2, 200);
    m_tbl->setColumnWidth(4, 80);
    m_mainLayout->addWidget(m_tbl, 1);
}

void FileAssocPage::refreshData()
{
    m_tbl->setRowCount(0);
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.exec("SELECT ext,assoc_program,normal_value,current_value,risk_level FROM file_assoc ORDER BY id DESC LIMIT 100");
        while (q.next()) {
            int row = m_tbl->rowCount(); m_tbl->insertRow(row);
            m_tbl->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));
            m_tbl->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
            m_tbl->setItem(row,2,new QTableWidgetItem(q.value(2).toString()));
            m_tbl->setItem(row,3,new QTableWidgetItem(q.value(3).toString()));
            QString risk = q.value(4).toString();
            QTableWidgetItem *ri = new QTableWidgetItem(risk=="high"?"高危":risk=="medium"?"中危":"正常");
            ri->setForeground(risk=="high"?QColor("#ef5350"):risk=="medium"?QColor("#ff9800"):QColor("#4caf50"));
            ri->setTextAlignment(Qt::AlignCenter);
            m_tbl->setItem(row,4,ri);
        }
    }
    if (m_tbl->rowCount() == 0) {
        QList<QStringList> demo = {
            {".exe","应用程序","exefile\\shell\\open\\command: \"%1\" %*","exefile\\shell\\open\\command: \"C:\\Windows\\Temp\\svchost32.exe\" \"%1\" %*","高危"},
            {".txt","记事本","txtfile\\shell\\open\\command: notepad.exe %1","txtfile\\shell\\open\\command: notepad.exe %1","正常"},
            {".html","Chrome","htmlfile\\shell\\open\\command: chrome.exe %1","htmlfile\\shell\\open\\command: C:\\Windows\\Temp\\browser.exe %1","中危"},
            {".pdf","Adobe Reader","AcroExch.Document\\shell\\open\\command: AcroRd32.exe %1","AcroExch.Document\\shell\\open\\command: AcroRd32.exe %1","正常"},
        };
        for (const QStringList &d : demo) {
            int r = m_tbl->rowCount(); m_tbl->insertRow(r);
            for (int c = 0; c < d.size(); ++c) {
                QTableWidgetItem *it = new QTableWidgetItem(d[c]);
                if (c==4) {
                    it->setForeground(d[c]=="高危"?QColor("#ef5350"):d[c]=="中危"?QColor("#ff9800"):QColor("#4caf50"));
                    it->setTextAlignment(Qt::AlignCenter);
                }
                m_tbl->setItem(r,c,it);
            }
        }
    }
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}
