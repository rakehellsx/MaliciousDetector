#include "pages/SampleExtractPage.h"
#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QFileDialog>
#include <QFileInfo>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QHeaderView>
#include <QLabel>
#include <QFont>
#include <QDateTime>

SampleExtractPage::SampleExtractPage(QWidget *parent)
    : BasePage("样本提取", parent)
{
    setupUi();
    refreshData();
}

void SampleExtractPage::setupUi()
{
    // 控制栏
    QHBoxLayout *fileRow = new QHBoxLayout;
    fileRow->setContentsMargins(0,0,0,8);
    m_editPath = new QLineEdit;
    m_editPath->setPlaceholderText("输入样本文件路径或拖拽文件...");
    m_editPath->setStyleSheet("QLineEdit{font-size:12px;padding:5px 8px;border:1px solid #d0d7e3;border-radius:3px;}");

    auto makeBtn = [](const QString &text, const QString &bg) -> QPushButton* {
        QPushButton *b = new QPushButton(text);
        b->setFixedWidth(90);
        b->setStyleSheet(QString("QPushButton{background:%1;color:#fff;border:none;border-radius:3px;"
                                 "padding:5px 10px;font-size:12px;}"
                                 "QPushButton:hover{opacity:0.9;}").arg(bg));
        return b;
    };
    m_btnBrowse  = makeBtn("浏览", "#595959"); m_btnBrowse->setFixedWidth(70);
    m_btnExtract = makeBtn("提取样本", "#1a3a6a");

    connect(m_btnBrowse, &QPushButton::clicked, [this](){
        QString p = QFileDialog::getOpenFileName(this, "选择文件", "", "所有文件 (*.*)");
        if (!p.isEmpty()) m_editPath->setText(p);
    });
    connect(m_btnExtract, &QPushButton::clicked, this, &SampleExtractPage::onExtract);

    fileRow->addWidget(m_editPath, 1);
    fileRow->addWidget(m_btnBrowse);
    fileRow->addWidget(m_btnExtract);
    m_mainLayout->addLayout(fileRow);

    // 表格
    m_tbl = new QTableWidget(0, 9);
    m_tbl->setHorizontalHeaderLabels({
        "文件名", "来源", "文件类型", "大小",
        "MD5", "SHA256", "原始创建时间", "原始修改时间", "提取时间"
    });
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tbl->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    m_tbl->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    m_tbl->verticalHeader()->setVisible(false);
    m_tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tbl->setAlternatingRowColors(true);
    m_tbl->setStyleSheet(
        "QTableWidget{border:1px solid #d0d7e3;font-size:12px;}"
        "QHeaderView::section{background:#e8ecf4;padding:5px 8px;font-weight:600;border:1px solid #d0d7e3;}"
        "QTableWidget::item{padding:5px 8px;}"
        "QTableWidget::item:alternate{background:#fafbfd;}");

    m_lblSummary = new QLabel;
    m_lblSummary->setStyleSheet("font-size:11px;color:#8c8c8c;padding:3px 2px;");

    m_mainLayout->addWidget(m_tbl, 1);
    m_mainLayout->addWidget(m_lblSummary);
}

void SampleExtractPage::refreshData()
{
    m_tbl->setRowCount(0);
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    bool loaded = false;

    if (db.isOpen()) {
        QSqlQuery q(db);
        q.exec("SELECT file_name,source_type,file_type,file_size,md5,sha256,"
               "original_create_time,original_modify_time,extract_time "
               "FROM sample_extract ORDER BY id DESC LIMIT 100");
        while (q.next()) {
            loaded = true;
            int row = m_tbl->rowCount(); m_tbl->insertRow(row);
            m_tbl->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));

            QString src = q.value(1).toString();
            QTableWidgetItem *srcItem = new QTableWidgetItem(src);
            srcItem->setForeground(src=="动态"?QColor("#1890ff"):QColor("#52c41a"));
            QFont sf = srcItem->font(); sf.setBold(true); srcItem->setFont(sf);
            m_tbl->setItem(row,1,srcItem);

            m_tbl->setItem(row,2,new QTableWidgetItem(q.value(2).toString()));
            m_tbl->setItem(row,3,new QTableWidgetItem(
                QString::number(q.value(3).toLongLong()/1024)+" KB"));

            QTableWidgetItem *md5i = new QTableWidgetItem(q.value(4).toString());
            md5i->setFont(QFont("Consolas",11));
            m_tbl->setItem(row,4,md5i);

            QTableWidgetItem *sha256i = new QTableWidgetItem(q.value(5).toString());
            sha256i->setFont(QFont("Consolas",11));
            m_tbl->setItem(row,5,sha256i);

            m_tbl->setItem(row,6,new QTableWidgetItem(q.value(6).toString()));
            m_tbl->setItem(row,7,new QTableWidgetItem(q.value(7).toString()));
            m_tbl->setItem(row,8,new QTableWidgetItem(q.value(8).toString()));
        }
    }

    // 无数据时显示空表，等待外部入库

    m_lblSummary->setText(QString("共 %1 个样本").arg(m_tbl->rowCount()));
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void SampleExtractPage::onExtract()
{
    QString path = m_editPath->text().trimmed();
    if (path.isEmpty()) { m_lblStatus->setText("请先选择文件"); return; }
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.prepare("INSERT INTO sample_extract(file_path,file_name,source_type,file_type,file_size,md5,sha256,"
                  "original_create_time,original_modify_time,extract_time) VALUES(?,?,?,?,?,?,?,?,?,?)");
        QFileInfo fi(path);
        q.addBindValue(path);
        q.addBindValue(fi.fileName());
        q.addBindValue("静态");
        q.addBindValue("PE32");
        q.addBindValue(fi.size());
        q.addBindValue("（待计算）");
        q.addBindValue("（待计算）");
        q.addBindValue(fi.birthTime().toString("yyyy-MM-dd HH:mm:ss"));
        q.addBindValue(fi.lastModified().toString("yyyy-MM-dd HH:mm:ss"));
        q.addBindValue(QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss"));
        q.exec();
        DatabaseManager::instance()->writeLog(m_role, m_username, "样本提取", fi.fileName(), "success");
    }
    refreshData();
    m_lblStatus->setText("已提取：" + path);
}
