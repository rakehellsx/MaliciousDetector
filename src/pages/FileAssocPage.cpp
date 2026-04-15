#include "pages/FileAssocPage.h"
#include "ui_FileAssocPage.h"

#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QDateTime>
#include <QFont>

FileAssocPage::FileAssocPage(QWidget *parent)
    : BasePage("文件关联检测", parent)
{
    ui = new Ui::FileAssocPage();
    ui->setupUi(this);
    postSetupUi();
    m_tbl = ui->m_tbl;
    m_btnScan = ui->m_btnScan;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbRisk = ui->m_cmbRisk;
    m_lblSummary = ui->m_lblSummary;
    m_lblStatus = ui->m_lblStatus;
    refreshData();
}

void FileAssocPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbRisk->setCurrentIndex(0);
    onQuery();
}

void FileAssocPage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     riskIdx = m_cmbRisk->currentIndex();
    QStringList riskMap = {"", "high", "medium", "low"};
    QString riskFilter = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";

    QString sql = "SELECT ext,assoc_type,original_cmd,current_cmd,risk_level "
                  "FROM file_assoc_scan WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (ext LIKE ? OR assoc_type LIKE ? OR current_cmd LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like;
    }
    if (!riskFilter.isEmpty()) {
        sql += " AND risk_level = ?";
        binds << riskFilter;
    }
    sql += " ORDER BY CASE risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void FileAssocPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    int highCount = 0, midCount = 0;

    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row, 0, new QTableWidgetItem(m["ext"].toString()));
        m_tbl->setItem(row, 1, new QTableWidgetItem(m["assoc_type"].toString()));
        QTableWidgetItem *ni = new QTableWidgetItem(m["original_cmd"].toString());
        ni->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 2, ni);
        QTableWidgetItem *ci = new QTableWidgetItem(m["current_cmd"].toString());
        ci->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 3, ci);

        QString risk = m["risk_level"].toString();
        if (risk == "high") highCount++;
        else if (risk == "medium") midCount++;
        QString riskText = (risk=="high") ? "高危（已篡改）" : (risk=="medium") ? "中危" : "低危";
        QTableWidgetItem *ri = new QTableWidgetItem(riskText);
        QFont rf = ri->font(); rf.setBold(true); ri->setFont(rf);
        if (risk == "high") {
            ri->setForeground(QColor("#f5222d"));
            for (int c = 0; c < 5; c++)
                if (m_tbl->item(row, c)) m_tbl->item(row, c)->setBackground(QColor("#fff1f0"));
            if (m["original_cmd"].toString() != m["current_cmd"].toString())
                ci->setForeground(QColor("#f5222d"));
        } else if (risk == "medium") {
            ri->setForeground(QColor("#fa8c16"));
            for (int c = 0; c < 5; c++)
                if (m_tbl->item(row, c)) m_tbl->item(row, c)->setBackground(QColor("#fffbe6"));
        } else {
            ri->setForeground(QColor("#52c41a"));
        }
        m_tbl->setItem(row, 4, ri);
    }

    QString summary = QString("共 %1 条").arg(rows.size());
    if (highCount > 0) summary += QString(" ｜ %1 条高危（已篡改）").arg(highCount);
    if (midCount > 0)  summary += QString(" ｜ %1 条中危").arg(midCount);
    m_lblSummary->setText(summary);
}
