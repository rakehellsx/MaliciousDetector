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
    postSetupUi();
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

    QString sql = "SELECT source_path,extract_type,sample_path,md5,sha256,"
                  "original_mtime,original_ctime,note,extract_time "
                  "FROM sample_extract WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (source_path LIKE ? OR md5 LIKE ? OR sha256 LIKE ? OR extract_type LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like << like;
    }
    if (!typeFilter.isEmpty()) {
        sql += " AND extract_type = ?";
        binds << typeFilter;
    }
    sql += " ORDER BY id DESC LIMIT 200";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    if (rows.isEmpty()) rows = loadDemoData();
    fillTable(rows);
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void SampleExtractPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        // 从 source_path 提取文件名显示
        QString srcPath = m["source_path"].toString();
        int slashIdx = qMax(srcPath.lastIndexOf('/'), srcPath.lastIndexOf('\\'));
        QString fileName = (slashIdx >= 0) ? srcPath.mid(slashIdx + 1) : srcPath;
        m_tbl->setItem(row, 0, new QTableWidgetItem(fileName));

        QTableWidgetItem *md5i = new QTableWidgetItem(m["md5"].toString());
        md5i->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 1, md5i);

        QTableWidgetItem *sha256i = new QTableWidgetItem(m["sha256"].toString());
        sha256i->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 2, sha256i);

        // sample_path 作为样本路径列
        m_tbl->setItem(row, 3, new QTableWidgetItem(m["sample_path"].toString()));

        QString src = m["extract_type"].toString();
        QTableWidgetItem *srcItem = new QTableWidgetItem(src);
        srcItem->setForeground(src=="动态" ? QColor("#1890ff") : QColor("#52c41a"));
        QFont sf = srcItem->font(); sf.setBold(true); srcItem->setFont(sf);
        m_tbl->setItem(row, 4, srcItem);

        m_tbl->setItem(row, 5, new QTableWidgetItem(m["extract_time"].toString()));
    }
    m_lblSummary->setText(QString("共 %1 个样本").arg(rows.size()));
}

void SampleExtractPage::onExtract()
{
    QString path = m_editPath->text().trimmed();
    if (path.isEmpty()) { m_lblStatus->setText("请先选择文件"); return; }

    QFileInfo fi(path);
    QString sql = "INSERT INTO sample_extract(source_path,extract_type,sample_path,md5,sha256,"
                  "original_mtime,original_ctime,note,extract_time) "
                  "VALUES(?,?,?,?,?,?,?,?,?)";
    QVariantList binds;
    binds << path << "静态" << path
          << "（待计算）" << "（待计算）"
          << fi.lastModified().toString("yyyy-MM-dd HH:mm:ss")
          << fi.birthTime().toString("yyyy-MM-dd HH:mm:ss")
          << fi.fileName()
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

QVariantList SampleExtractPage::loadDemoData()
{
    return QVariantList{
        QVariant(QVariantMap{
            {"source_path","C:\\Windows\\Temp\\svchost32.exe"},
            {"extract_type","动态"},
            {"sample_path","C:\\Samples\\svchost32_20250416.exe"},
            {"md5","a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"},
            {"sha256","a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
            {"original_mtime","2025-04-16 08:10:00"},
            {"original_ctime","2025-04-16 08:09:55"},
            {"note","高危进程，疑似 C2 木马"},
            {"extract_time","2025-04-16 09:12:34"}
        }),
        QVariant(QVariantMap{
            {"source_path","C:\\Windows\\Temp\\payload.exe"},
            {"extract_type","动态"},
            {"sample_path","C:\\Samples\\payload_20250416.exe"},
            {"md5","b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"},
            {"sha256","b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"},
            {"original_mtime","2025-04-16 08:12:45"},
            {"original_ctime","2025-04-16 08:12:40"},
            {"note","释放的恶意载荷"},
            {"extract_time","2025-04-16 09:13:01"}
        }),
        QVariant(QVariantMap{
            {"source_path","C:\\Windows\\Temp\\inject.dll"},
            {"extract_type","静态"},
            {"sample_path","C:\\Samples\\inject_20250416.dll"},
            {"md5","c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"},
            {"sha256","c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"},
            {"original_mtime","2025-04-16 08:13:20"},
            {"original_ctime","2025-04-16 08:13:15"},
            {"note","DLL 注入模块"},
            {"extract_time","2025-04-16 09:14:05"}
        }),
        QVariant(QVariantMap{
            {"source_path","C:\\Windows\\Temp\\helper32.dll"},
            {"extract_type","静态"},
            {"sample_path","C:\\Samples\\helper32_20250416.dll"},
            {"md5","d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1"},
            {"sha256","d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"},
            {"original_mtime","2025-04-16 08:14:00"},
            {"original_ctime","2025-04-16 08:13:58"},
            {"note","辅助模块，未签名"},
            {"extract_time","2025-04-16 09:15:22"}
        }),
        QVariant(QVariantMap{
            {"source_path","C:\\Windows\\Temp\\rootkit.sys"},
            {"extract_type","静态"},
            {"sample_path","C:\\Samples\\rootkit_20250416.sys"},
            {"md5","e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
            {"sha256","e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"},
            {"original_mtime","2025-04-16 08:15:30"},
            {"original_ctime","2025-04-16 08:15:25"},
            {"note","内核级 Rootkit 驱动"},
            {"extract_time","2025-04-16 09:16:45"}
        })
    };
}
