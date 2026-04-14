#include "pages/CertScanPage.h"
#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QSplitter>
#include <QFileDialog>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QHeaderView>
#include <QDateTime>

CertScanPage::CertScanPage(QWidget *parent) : BasePage("\u6570\u5b57\u8bc1\u4e66\u68c0\u6d4b", parent) { setupUi(); refreshData(); }

void CertScanPage::setupUi()
{
    QHBoxLayout *fileRow = new QHBoxLayout;
    m_editPath = new QLineEdit;
    m_editPath->setObjectName("searchInput");
    m_editPath->setPlaceholderText("\u8f93\u5165\u6587\u4ef6\u8def\u5f84...");
    m_btnBrowse = new QPushButton("\u6d4f \u89c8");
    m_btnBrowse->setObjectName("btnSecondary");
    m_btnBrowse->setFixedWidth(72);
    m_btnScan = new QPushButton("\u9a8c\u8bc1\u8bc1\u4e66");
    m_btnScan->setObjectName("btnPrimary");
    m_btnScan->setFixedWidth(88);
    connect(m_btnBrowse, &QPushButton::clicked, this, &CertScanPage::onBrowseFile);
    connect(m_btnScan,   &QPushButton::clicked, this, &CertScanPage::onStartScan);
    fileRow->addWidget(m_editPath, 1);
    fileRow->addWidget(m_btnBrowse);
    fileRow->addWidget(m_btnScan);
    m_mainLayout->addLayout(fileRow);

    QSplitter *sp = new QSplitter(Qt::Vertical);
    // DB字段: file_name, signer, issuer, timestamp, sign_status, tamper_status
    m_tblResults = new QTableWidget(0, 6);
    m_tblResults->setHorizontalHeaderLabels({"\u6587\u4ef6\u540d", "\u7b7e\u540d\u8005", "\u989c\u53d1\u673a\u6784", "\u65f6\u95f4\u6233", "\u7b7e\u540d\u72b6\u6001", "\u7bf9\u6539\u68c0\u6d4b"});
    styleTable(m_tblResults);
    m_tblResults->setColumnWidth(0, 160);
    m_tblResults->setColumnWidth(1, 160);
    m_tblResults->setColumnWidth(2, 160);
    m_tblResults->setColumnWidth(3, 120);
    m_tblResults->setColumnWidth(4, 80);
    connect(m_tblResults, &QTableWidget::cellClicked, this, &CertScanPage::onRowSelected);
    sp->addWidget(m_tblResults);

    m_txtDetail = new QTextEdit;
    m_txtDetail->setReadOnly(true);
    m_txtDetail->setObjectName("codeView");
    m_txtDetail->setPlaceholderText("\u9009\u62e9\u8bb0\u5f55\u67e5\u770b\u8bc1\u4e66\u8be6\u60c5...");
    sp->addWidget(m_txtDetail);
    sp->setStretchFactor(0, 2);
    sp->setStretchFactor(1, 1);
    m_mainLayout->addWidget(sp, 1);
}

void CertScanPage::refreshData()
{
    m_tblResults->setRowCount(0);
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        // 使用表实际字段，通过 CASE 转换为显示值
        q.exec("SELECT "
               "COALESCE(NULLIF(subject,''), file_path) AS file_name, "
               "COALESCE(NULLIF(subject,''), '--') AS signer, "
               "COALESCE(NULLIF(issuer,''), '--') AS issuer, "
               "COALESCE(NULLIF(not_before,''), '--') AS ts, "
               "CASE WHEN has_signature=0 THEN '\u65e0\u7b7e\u540d' "
                    "WHEN signature_valid=1 AND not_expired=1 THEN '\u6709\u6548' "
                    "WHEN not_expired=0 THEN '\u8bc1\u4e66\u8fc7\u671f' "
                    "ELSE '\u65e0\u6548' END AS sign_status, "
               "CASE WHEN file_tampered=1 THEN '\u7bf9\u6539' "
                    "WHEN has_signature=0 THEN '--' "
                    "ELSE '\u672a\u7bf9\u6539' END AS tamper_status "
               "FROM cert_scan ORDER BY id DESC LIMIT 100");
        while (q.next()) {
            int row = m_tblResults->rowCount();
            m_tblResults->insertRow(row);
            m_tblResults->setItem(row, 0, new QTableWidgetItem(q.value(0).toString()));
            m_tblResults->setItem(row, 1, new QTableWidgetItem(q.value(1).toString()));
            m_tblResults->setItem(row, 2, new QTableWidgetItem(q.value(2).toString()));
            m_tblResults->setItem(row, 3, new QTableWidgetItem(q.value(3).toString()));
            QString st = q.value(4).toString();
            QTableWidgetItem *si = new QTableWidgetItem(st);
            si->setForeground(st == "\u6709\u6548" ? QColor("#4caf50") : QColor("#ef5350"));
            si->setTextAlignment(Qt::AlignCenter);
            m_tblResults->setItem(row, 4, si);
            QString ts = q.value(5).toString();
            QTableWidgetItem *ti = new QTableWidgetItem(ts);
            ti->setForeground(ts == "\u672a\u7bf9\u6539" ? QColor("#4caf50") : QColor("#ef5350"));
            ti->setTextAlignment(Qt::AlignCenter);
            m_tblResults->setItem(row, 5, ti);
            // 高风险行背景
            if (st != "\u6709\u6548" || ts != "\u672a\u7bf9\u6539")
                for (int c = 0; c < 6; c++)
                    if (m_tblResults->item(row, c)) m_tblResults->item(row, c)->setBackground(QColor("#fff1f0"));
        }
    }
    // 无数据时显示空表，等待外部入库
    m_lblStatus->setText("\u5df2\u5237\u65b0\uff1a" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void CertScanPage::onBrowseFile() {
    QString p = QFileDialog::getOpenFileName(this, "\u9009\u62e9\u6587\u4ef6", "", "\u6240\u6709\u6587\u4ef6 (*.*)");
    if (!p.isEmpty()) m_editPath->setText(p);
}

void CertScanPage::onStartScan() {
    m_lblStatus->setText("\u5df2\u63d0\u4ea4\u8bc1\u4e66\u9a8c\u8bc1\uff1a" + m_editPath->text());
    DatabaseManager::instance()->writeLog(m_role, m_username, "\u6570\u5b57\u8bc1\u4e66\u68c0\u6d4b", m_editPath->text(), "success");
}

void CertScanPage::onRowSelected(int row, int) {
    m_txtDetail->setPlainText(
        "\u6587\u4ef6\u540d\uff1a    " + (m_tblResults->item(row,0)?m_tblResults->item(row,0)->text():"--") + "\n"
        "\u7b7e\u540d\u8005\uff1a    " + (m_tblResults->item(row,1)?m_tblResults->item(row,1)->text():"--") + "\n"
        "\u989c\u53d1\u673a\u6784\uff1a  " + (m_tblResults->item(row,2)?m_tblResults->item(row,2)->text():"--") + "\n"
        "\u65f6\u95f4\u6233\uff1a    " + (m_tblResults->item(row,3)?m_tblResults->item(row,3)->text():"--") + "\n"
        "\u7b7e\u540d\u72b6\u6001\uff1a  " + (m_tblResults->item(row,4)?m_tblResults->item(row,4)->text():"--") + "\n"
        "\u7bf9\u6539\u68c0\u6d4b\uff1a  " + (m_tblResults->item(row,5)?m_tblResults->item(row,5)->text():"--") + "\n\n"
        "\u8be6\u7ec6\u8bc1\u4e66\u94fe\uff1a\uff08\u5f85\u68c0\u6d4b\u5f15\u64ce\u586b\u5145\uff09\n"
        "  \u6839\u8bc1\u4e66 \u2192 \u4e2d\u95f4\u8bc1\u4e66 \u2192 \u6700\u7ec8\u8bc1\u4e66\n"
    );
}
