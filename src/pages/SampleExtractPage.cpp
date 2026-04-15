#include "pages/SampleExtractPage.h"
#include "ui_SampleExtractPage.h"

#include "DatabaseManager.h"
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QFileInfo>
#include <QHeaderView>
#include <QLabel>
#include <QFont>
#include <QDateTime>

SampleExtractPage::SampleExtractPage(QWidget *parent)
    : BasePage("样本提取", parent)
{
    ui = new Ui::SampleExtractPage();
    ui->setupUi(this);
    m_editPath = ui->m_editPath;
    m_btnBrowse = ui->m_btnBrowse;
    m_btnExtract = ui->m_btnExtract;
    m_tbl = ui->m_tbl;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbType = ui->m_cmbType;
    m_lblSummary = ui->m_lblSummary;
    m_lblStatus = ui->m_lblStatus;
    refreshData();
}

void SampleExtractPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbType->setCurrentIndex(0);
    onQuery();
}

void SampleExtractPage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     typeIdx = m_cmbType->currentIndex();
    QStringList typeMap = {"", "静态", "动态"};
    QString typeFilter = (typeIdx > 0 && typeIdx < typeMap.size()) ? typeMap[typeIdx] : "";

    QString sql = "SELECT file_name,source_type,file_type,file_size,md5,sha256,"
                  "original_create_time,original_modify_time,extract_time "
                  "FROM sample_extract WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (file_name LIKE ? OR md5 LIKE ? OR sha256 LIKE ? OR source_type LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like << like;
    }
    if (!typeFilter.isEmpty()) {
        sql += " AND source_type = ?";
        binds << typeFilter;
    }
    sql += " ORDER BY id DESC LIMIT 200";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void SampleExtractPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row, 0, new QTableWidgetItem(m["file_name"].toString()));

        QString src = m["source_type"].toString();
        QTableWidgetItem *srcItem = new QTableWidgetItem(src);
        srcItem->setForeground(src=="动态" ? QColor("#1890ff") : QColor("#52c41a"));
        QFont sf = srcItem->font(); sf.setBold(true); srcItem->setFont(sf);
        m_tbl->setItem(row, 1, srcItem);

        m_tbl->setItem(row, 2, new QTableWidgetItem(m["file_type"].toString()));
        m_tbl->setItem(row, 3, new QTableWidgetItem(
            QString::number(m["file_size"].toLongLong()/1024) + " KB"));

        QTableWidgetItem *md5i = new QTableWidgetItem(m["md5"].toString());
        md5i->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 4, md5i);

        QTableWidgetItem *sha256i = new QTableWidgetItem(m["sha256"].toString());
        sha256i->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 5, sha256i);

        m_tbl->setItem(row, 6, new QTableWidgetItem(m["original_create_time"].toString()));
        m_tbl->setItem(row, 7, new QTableWidgetItem(m["original_modify_time"].toString()));
        m_tbl->setItem(row, 8, new QTableWidgetItem(m["extract_time"].toString()));
    }
    m_lblSummary->setText(QString("共 %1 个样本").arg(rows.size()));
}

void SampleExtractPage::onExtract()
{
    QString path = m_editPath->text().trimmed();
    if (path.isEmpty()) { m_lblStatus->setText("请先选择文件"); return; }

    QFileInfo fi(path);
    QString sql = "INSERT INTO sample_extract(file_path,file_name,source_type,file_type,file_size,"
                  "md5,sha256,original_create_time,original_modify_time,extract_time) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?)";
    QVariantList binds;
    binds << path << fi.fileName() << "静态" << "PE32" << fi.size()
          << "（待计算）" << "（待计算）"
          << fi.birthTime().toString("yyyy-MM-dd HH:mm:ss")
          << fi.lastModified().toString("yyyy-MM-dd HH:mm:ss")
          << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    {
        QSqlDatabase db = QSqlDatabase::database("main_conn");
        if (db.isOpen()) {
            QSqlQuery q(db);
            q.prepare(sql);
            for (const QVariant &b : binds) q.addBindValue(b);
            q.exec();
        }
    }
    DatabaseManager::instance()->writeLog(m_role, m_username, "样本提取", fi.fileName(), "success");
    refreshData();
    m_lblStatus->setText("已提取：" + path);
}
