#include "pages/CertScanPage.h"
#include "ui_CertScanPage.h"
#include "DatabaseManager.h"
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QHeaderView>
#include <QDateTime>

CertScanPage::CertScanPage(QWidget *parent) : BasePage("数字证书检测", parent) {
    ui = new Ui::CertScanPage();
    ui->setupUi(this);
    m_edtKeyword    = ui->m_edtKeyword;
    m_cmbCertStatus = ui->m_cmbCertStatus;
    m_tbl           = ui->m_tbl;

    QPushButton *btnQuery = findChild<QPushButton*>("btnQuery");
    if (btnQuery) connect(btnQuery, &QPushButton::clicked, this, &CertScanPage::onQuery);
    connect(m_edtKeyword, &QLineEdit::returnPressed, this, &CertScanPage::onQuery);
    connect(m_cmbCertStatus, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &CertScanPage::onQuery);
    connect(m_tbl, &QTableWidget::cellClicked, this, &CertScanPage::onRowSelected);

    refreshData();
}

void CertScanPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbCertStatus->setCurrentIndex(0);
    onQuery();
}

void CertScanPage::onQuery()
{
    QString kw        = m_edtKeyword->text().trimmed();
    int     statusIdx = m_cmbCertStatus->currentIndex();

    QString sql =
        "SELECT "
        "COALESCE(NULLIF(subject,''), file_path) AS file_name, "
        "COALESCE(NULLIF(subject,''), '--') AS signer, "
        "COALESCE(NULLIF(issuer,''), '--') AS issuer, "
        "COALESCE(NULLIF(not_before,''), '--') AS ts, "
        "CASE WHEN has_signature=0 THEN '未签名' "
             "WHEN signature_valid=1 AND not_expired=1 THEN '已签名' "
             "WHEN not_expired=0 THEN '证书过期' "
             "ELSE '无效' END AS sign_status, "
        "CASE WHEN file_tampered=1 THEN '篡改' "
             "WHEN has_signature=0 THEN '--' "
             "ELSE '未篡改' END AS tamper_status "
        "FROM cert_scan WHERE 1=1";

    QVariantList binds;
    if (!kw.isEmpty()) {
        sql += " AND (file_path LIKE ? OR subject LIKE ? OR issuer LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like;
    }
    switch (statusIdx) {
        case 1: sql += " AND has_signature=1"; break;
        case 2: sql += " AND has_signature=0"; break;
        case 3: sql += " AND signature_valid=1 AND not_expired=1"; break;
        case 4: sql += " AND not_expired=0"; break;
        case 5: sql += " AND file_tampered=1"; break;
        default: break;
    }
    sql += " ORDER BY id DESC LIMIT 200";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void CertScanPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = m_tbl->rowCount();
        m_tbl->insertRow(row);
        m_tbl->setItem(row, 0, new QTableWidgetItem(m["file_name"].toString()));
        m_tbl->setItem(row, 1, new QTableWidgetItem(m["signer"].toString()));
        m_tbl->setItem(row, 2, new QTableWidgetItem(m["issuer"].toString()));
        m_tbl->setItem(row, 3, new QTableWidgetItem(m["ts"].toString()));

        QString st = m["sign_status"].toString();
        QTableWidgetItem *si = new QTableWidgetItem(st);
        si->setForeground(st == "已签名" ? QColor("#4caf50") : QColor("#ef5350"));
        si->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(row, 4, si);

        QString ts = m["tamper_status"].toString();
        QTableWidgetItem *ti = new QTableWidgetItem(ts);
        ti->setForeground(ts == "未篡改" ? QColor("#4caf50") : QColor("#ef5350"));
        ti->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(row, 5, ti);

        if (st != "已签名" || ts == "篡改")
            for (int c = 0; c < 6; c++)
                if (m_tbl->item(row, c)) m_tbl->item(row, c)->setBackground(QColor("#fff1f0"));
    }
}

void CertScanPage::onRowSelected(int row, int)
{
    if (row < 0 || row >= m_tbl->rowCount()) return;
    QString info = QString("文件: %1 | 签名: %2 | 完整性: %3")
        .arg(m_tbl->item(row,0) ? m_tbl->item(row,0)->text() : "--")
        .arg(m_tbl->item(row,4) ? m_tbl->item(row,4)->text() : "--")
        .arg(m_tbl->item(row,5) ? m_tbl->item(row,5)->text() : "--");
    m_lblStatus->setText(info);
}
