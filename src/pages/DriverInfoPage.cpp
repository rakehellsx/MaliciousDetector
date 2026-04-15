#include "pages/DriverInfoPage.h"
#include "ui_DriverInfoPage.h"

#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

DriverInfoPage::DriverInfoPage(QWidget *parent)
    : BasePage("驱动信息", parent)
{
    ui = new Ui::DriverInfoPage();
    ui->setupUi(this);
    postSetupUi();
    m_tbl = ui->m_tbl;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbType = findChild<QComboBox*>("m_cmbType");
    m_cmbSigned = ui->m_cmbSigned;
    m_cmbRisk = findChild<QComboBox*>("m_cmbRisk");
    m_lblSummary = ui->m_lblSummary;
    m_lblStatus = ui->m_lblStatus;
    refreshData();
}

void DriverInfoPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbType->setCurrentIndex(0);
    m_cmbSigned->setCurrentIndex(0);
    m_cmbRisk->setCurrentIndex(0);
    onQuery();
}

void DriverInfoPage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     typeIdx = m_cmbType->currentIndex();
    int     signIdx = m_cmbSigned->currentIndex();
    int     riskIdx = m_cmbRisk->currentIndex();
    QStringList typeMap = {"", "内核驱动", "设备驱动", "第三方"};
    QStringList riskMap = {"", "高危", "中危", "低危"};
    QString typeFilter = (typeIdx > 0 && typeIdx < typeMap.size()) ? typeMap[typeIdx] : "";
    QString riskFilter = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";

    QString sql = "SELECT name,type,publisher,modified_time,path,is_signed,risk FROM driver_info WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (name LIKE ? OR publisher LIKE ? OR path LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like;
    }
    if (!typeFilter.isEmpty()) {
        sql += " AND type = ?";
        binds << typeFilter;
    }
    if (signIdx == 1) {
        sql += " AND is_signed = 1";
    } else if (signIdx == 2) {
        sql += " AND is_signed = 0";
    }
    if (!riskFilter.isEmpty()) {
        sql += " AND risk = ?";
        binds << riskFilter;
    }
    sql += " ORDER BY risk DESC, id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);

    int unsignedCount = 0;
    for (const QVariant &v : rows)
        if (v.toMap()["is_signed"].toInt() == 0) unsignedCount++;
    m_lblSummary->setText(QString("共 %1 个驱动，其中未签名 %2 个").arg(rows.size()).arg(unsignedCount));
    m_lblStatus->setText(QString("共 %1 条记录").arg(rows.size()));
}

void DriverInfoPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    QStringList typeMap = {"", "内核驱动", "设备驱动", "第三方"};
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        int typeVal = m["type"].toInt();
        QString typeStr = (typeVal > 0 && typeVal < typeMap.size()) ? typeMap[typeVal] : m["type"].toString();
        m_tbl->setItem(r, 1, new QTableWidgetItem(typeStr));
        m_tbl->setItem(r, 2, new QTableWidgetItem(m["publisher"].toString()));
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["modified_time"].toString()));
        m_tbl->setItem(r, 4, new QTableWidgetItem(m["path"].toString()));
        bool isSigned = m["is_signed"].toInt() != 0;
        QTableWidgetItem *si = new QTableWidgetItem(isSigned ? "已签名" : "未签名");
        si->setForeground(isSigned ? QColor("#4caf50") : QColor("#f5222d"));
        QFont sf = si->font(); sf.setBold(true); si->setFont(sf);
        si->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 5, si);
        QString risk = m["risk"].toString();
        auto *ri = new QTableWidgetItem(risk);
        if      (risk == "高危") ri->setForeground(QColor("#ef5350"));
        else if (risk == "中危") ri->setForeground(QColor("#ff9800"));
        else                     ri->setForeground(QColor("#4caf50"));
        ri->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 6, ri);
        if (risk == "高危" || !isSigned)
            for (int c = 0; c < 7; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff1f0"));
    }
}
