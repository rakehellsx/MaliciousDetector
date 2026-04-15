#include "pages/SharedResourcePage.h"
#include "ui_SharedResourcePage.h"

#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

SharedResourcePage::SharedResourcePage(QWidget *parent)
    : BasePage("共享资源", parent)
{
    ui = new Ui::SharedResourcePage();
    ui->setupUi(this);
    m_tbl = ui->m_tbl;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbRisk = ui->m_cmbRisk;
    m_lblStatus = ui->m_lblStatus;
    refreshData();
}

void SharedResourcePage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbRisk->setCurrentIndex(0);
    onQuery();
}

void SharedResourcePage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     riskIdx = m_cmbRisk->currentIndex();
    QStringList riskMap = {"", "高危", "中危", "低危"};
    QString riskFilter = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";

    QString sql = "SELECT name,path,type,permission,connected,risk FROM shared_resource WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (name LIKE ? OR path LIKE ? OR permission LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like;
    }
    if (!riskFilter.isEmpty()) {
        sql += " AND risk = ?";
        binds << riskFilter;
    }
    sql += " ORDER BY risk DESC, id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);
    m_lblStatus->setText(QString("共 %1 个共享资源").arg(rows.size()));
}

void SharedResourcePage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["path"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["type"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["permission"].toString()));
        bool connected = m["connected"].toInt() > 0;
        QTableWidgetItem *ci = new QTableWidgetItem(connected ? "是" : "否");
        ci->setForeground(connected ? QColor("#f5222d") : QColor("#4caf50"));
        ci->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 4, ci);
        QString risk = m["risk"].toString();
        auto *ri = new QTableWidgetItem(risk);
        if      (risk == "高危") ri->setForeground(QColor("#ef5350"));
        else if (risk == "中危") ri->setForeground(QColor("#ff9800"));
        else                     ri->setForeground(QColor("#4caf50"));
        ri->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 5, ri);
        if (risk == "高危")
            for (int c = 0; c < 6; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff1f0"));
    }
}
