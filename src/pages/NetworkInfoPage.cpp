#include "pages/NetworkInfoPage.h"
#include "ui_NetworkInfoPage.h"

#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

NetworkInfoPage::NetworkInfoPage(QWidget *parent)
    : BasePage("网络信息", parent)
{
    ui = new Ui::NetworkInfoPage();
    ui->setupUi(this);
    postSetupUi();
    m_tbl = ui->m_tbl;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbStatus = ui->m_cmbStatus;
    m_lblStatus = ui->m_lblStatus;
    refreshData();
}

void NetworkInfoPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbStatus->setCurrentIndex(0);
    onQuery();
}

void NetworkInfoPage::onQuery()
{
    QString kw     = m_edtKeyword->text().trimmed();
    int     stIdx  = m_cmbStatus->currentIndex();
    QString status = stIdx == 1 ? "已连接" : stIdx == 2 ? "断开" : "";

    QString sql = "SELECT name,ip,mask,gateway,mac,status FROM net_info WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (name LIKE ? OR ip LIKE ? OR mac LIKE ? OR gateway LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like << like;
    }
    if (!status.isEmpty()) {
        sql += " AND status = ?";
        binds << status;
    }
    sql += " ORDER BY id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}

void NetworkInfoPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["ip"].toString()));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["mask"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["gateway"].toString()));
        m_tbl->setItem(r, 4, new QTableWidgetItem(m["mac"].toString()));
        QString st = m["status"].toString();
        auto *si = new QTableWidgetItem(st);
        si->setForeground(st == "已连接" ? QColor("#4caf50") : QColor("#90caf9"));
        si->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 5, si);
    }
}
