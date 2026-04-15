#include "pages/DiskInfoPage.h"
#include "ui_DiskInfoPage.h"

#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

DiskInfoPage::DiskInfoPage(QWidget *parent)
    : BasePage("硬盘信息", parent)
{
    ui = new Ui::DiskInfoPage();
    ui->setupUi(this);
    postSetupUi();
    m_tbl = ui->m_tbl;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbType = ui->m_cmbType;
    m_lblStatus = findChild<QLabel*>("m_lblStatus");
    refreshData();
}

void DiskInfoPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbType->setCurrentIndex(0);
    onQuery();
}

void DiskInfoPage::onQuery()
{
    QString kw   = m_edtKeyword->text().trimmed();
    int     tIdx = m_cmbType->currentIndex();
    QStringList typeMap = {"", "本地磁盘", "可移动磁盘", "网络磁盘", "光驱"};
    QString typeFilter  = (tIdx > 0 && tIdx < typeMap.size()) ? typeMap[tIdx] : "";

    QString sql = "SELECT drive,type,filesystem,total_gb,free_gb,used_pct,serial FROM disk_info WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (drive LIKE ? OR filesystem LIKE ? OR serial LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like;
    }
    if (!typeFilter.isEmpty()) {
        sql += " AND type = ?";
        binds << typeFilter;
    }
    sql += " ORDER BY id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}

void DiskInfoPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["drive"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["type"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["filesystem"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(QString::number(m["total_gb"].toDouble(), 'f', 1)));
        m_tbl->setItem(r, 4, new QTableWidgetItem(QString::number(m["free_gb"].toDouble(), 'f', 1)));
        double pct = m["used_pct"].toDouble();
        auto *usage = new QTableWidgetItem(QString::number(pct, 'f', 1) + "%");
        if      (pct > 90) usage->setForeground(QColor("#ef5350"));
        else if (pct > 70) usage->setForeground(QColor("#ff9800"));
        else               usage->setForeground(QColor("#4caf50"));
        m_tbl->setItem(r, 5, usage);
        m_tbl->setItem(r, 6, new QTableWidgetItem(m["serial"].toString()));
    }
}
