#include "pages/SampleExtractPage.h"
#include <QHBoxLayout>
#include <QFileDialog>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QHeaderView>

SampleExtractPage::SampleExtractPage(QWidget *parent) : BasePage("样本提取", parent) { setupUi(); refreshData(); }

void SampleExtractPage::setupUi()
{
    QHBoxLayout *fileRow = new QHBoxLayout;
    m_editPath = new QLineEdit;
    m_editPath->setObjectName("searchInput");
    m_editPath->setPlaceholderText("输入样本路径或拖入文件...");
    m_btnBrowse = new QPushButton("浏 览");
    m_btnBrowse->setObjectName("btnSecondary");
    m_btnBrowse->setFixedWidth(72);
    m_btnExtract = new QPushButton("提取样本");
    m_btnExtract->setObjectName("btnPrimary");
    m_btnExtract->setFixedWidth(88);
    connect(m_btnBrowse,  &QPushButton::clicked, [this](){
        QString p = QFileDialog::getOpenFileName(this,"选择文件","","所有文件 (*.*)");
        if (!p.isEmpty()) m_editPath->setText(p);
    });
    connect(m_btnExtract, &QPushButton::clicked, this, &SampleExtractPage::onExtract);
    fileRow->addWidget(m_editPath, 1);
    fileRow->addWidget(m_btnBrowse);
    fileRow->addWidget(m_btnExtract);
    m_mainLayout->addLayout(fileRow);

    m_tbl = new QTableWidget(0, 8);
    m_tbl->setHorizontalHeaderLabels({"文件名","文件类型","大小","MD5","SHA256","原始创建时间","原始修改时间","提取时间"});
    styleTable(m_tbl);
    m_tbl->setColumnWidth(0, 160);
    m_tbl->setColumnWidth(1, 80);
    m_tbl->setColumnWidth(2, 80);
    m_tbl->setColumnWidth(3, 200);
    m_tbl->setColumnWidth(4, 200);
    m_mainLayout->addWidget(m_tbl, 1);
}

void SampleExtractPage::refreshData()
{
    m_tbl->setRowCount(0);
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.exec("SELECT file_name,file_type,file_size,md5,sha256,original_create_time,original_modify_time,extract_time "
               "FROM sample_extract ORDER BY id DESC LIMIT 100");
        while (q.next()) {
            int row = m_tbl->rowCount(); m_tbl->insertRow(row);
            m_tbl->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));
            m_tbl->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
            m_tbl->setItem(row,2,new QTableWidgetItem(QString::number(q.value(2).toLongLong()/1024)+" KB"));
            m_tbl->setItem(row,3,new QTableWidgetItem(q.value(3).toString()));
            m_tbl->setItem(row,4,new QTableWidgetItem(q.value(4).toString()));
            m_tbl->setItem(row,5,new QTableWidgetItem(q.value(5).toString()));
            m_tbl->setItem(row,6,new QTableWidgetItem(q.value(6).toString()));
            m_tbl->setItem(row,7,new QTableWidgetItem(q.value(7).toString()));
        }
    }
    if (m_tbl->rowCount() == 0) {
        QList<QStringList> demo = {
            {"svchost32.exe","PE32","48 KB","a1b2c3d4e5f67890abcdef1234567890","abcdef1234567890a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890","2025-11-19 08:30","2025-11-19 09:00","2025-11-20 09:41"},
            {"payload.dll","DLL","96 KB","f6e5d4c3b2a10987fedcba9876543210","fedcba9876543210f6e5d4c3b2a10987fedcba9876543210f6e5d4c3b2a10987","2025-11-18 14:00","2025-11-19 08:25","2025-11-20 09:42"},
        };
        for (const QStringList &d : demo) {
            int r = m_tbl->rowCount(); m_tbl->insertRow(r);
            for (int c = 0; c < d.size(); ++c)
                m_tbl->setItem(r,c,new QTableWidgetItem(d[c]));
        }
    }
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void SampleExtractPage::onExtract()
{
    QString path = m_editPath->text().trimmed();
    if (path.isEmpty()) { m_lblStatus->setText("请先选择文件"); return; }
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.prepare("INSERT INTO sample_extract(file_path,file_name,file_type,file_size,md5,sha256,"
                  "original_create_time,original_modify_time) VALUES(?,?,?,?,?,?,?,?)");
        QFileInfo fi(path);
        q.addBindValue(path);
        q.addBindValue(fi.fileName());
        q.addBindValue("PE32");
        q.addBindValue(fi.size());
        q.addBindValue("（待哈希计算）");
        q.addBindValue("（待哈希计算）");
        q.addBindValue(fi.birthTime().toString("yyyy-MM-dd HH:mm:ss"));
        q.addBindValue(fi.lastModified().toString("yyyy-MM-dd HH:mm:ss"));
        q.exec();
        DatabaseManager::instance()->writeLog(m_role, m_username, "样本提取", fi.fileName(), "success");
    }
    refreshData();
    m_lblStatus->setText("已提取：" + path);
}
