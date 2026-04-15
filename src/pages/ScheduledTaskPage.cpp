#include "pages/ScheduledTaskPage.h"
#include "ui_ScheduledTaskPage.h"

#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

ScheduledTaskPage::ScheduledTaskPage(QWidget *parent)
    : BasePage("计划任务", parent)
{
    ui = new Ui::ScheduledTaskPage();
    ui->setupUi(this);
    postSetupUi();
    m_tbl = ui->m_tbl;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbRisk = ui->m_cmbRisk;
    m_cmbStatus = ui->m_cmbStatus;
    m_lblSummary = ui->m_lblSummary;
    m_lblStatus = ui->m_lblStatus;
    refreshData();
}

void ScheduledTaskPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbRisk->setCurrentIndex(0);
    m_cmbStatus->setCurrentIndex(0);
    onQuery();
}

void ScheduledTaskPage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     riskIdx = m_cmbRisk->currentIndex();
    int     stIdx   = m_cmbStatus->currentIndex();
    QStringList riskMap = {"", "高危", "中危", "低危"};
    QStringList stMap   = {"", "已启用", "已禁用"};
    QString risk   = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";
    QString status = (stIdx   > 0 && stIdx   < stMap.size())   ? stMap[stIdx]   : "";

    QString sql = "SELECT name,trigger,action,path,status,last_run,risk FROM scheduled_task WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (name LIKE ? OR action LIKE ? OR path LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like;
    }
    if (!risk.isEmpty()) {
        sql += " AND risk = ?";
        binds << risk;
    }
    if (!status.isEmpty()) {
        sql += " AND status = ?";
        binds << status;
    }
    sql += " ORDER BY risk DESC, id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);

    int highRisk = 0;
    for (const QVariant &v : rows)
        if (v.toMap()["risk"].toString() == "高危") highRisk++;
    m_lblSummary->setText(QString("共 %1 个计划任务，其中高危 %2 个").arg(rows.size()).arg(highRisk));
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}

void ScheduledTaskPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["trigger"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["action"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["path"].toString()));
        m_tbl->setItem(r, 4, new QTableWidgetItem(m["status"].toString()));
        m_tbl->setItem(r, 5, new QTableWidgetItem(m["last_run"].toString()));
        QString risk = m["risk"].toString();
        auto *ri = new QTableWidgetItem(risk);
        if      (risk == "高危") ri->setForeground(QColor("#ef5350"));
        else if (risk == "中危") ri->setForeground(QColor("#ff9800"));
        else                     ri->setForeground(QColor("#4caf50"));
        ri->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 6, ri);
        if (risk == "高危")
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff1f0"));
    }
}
