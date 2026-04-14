#include "pages/CertScanPage.h"
#include <QHBoxLayout>
#include <QSplitter>
#include <QFileDialog>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QHeaderView>

CertScanPage::CertScanPage(QWidget *parent) : BasePage("数字证书检测", parent) { setupUi(); refreshData(); }

void CertScanPage::setupUi()
{
    QHBoxLayout *fileRow = new QHBoxLayout;
    m_editPath = new QLineEdit;
    m_editPath->setObjectName("searchInput");
    m_editPath->setPlaceholderText("输入文件路径...");
    m_btnBrowse = new QPushButton("浏 览");
    m_btnBrowse->setObjectName("btnSecondary");
    m_btnBrowse->setFixedWidth(72);
    m_btnScan = new QPushButton("验证证书");
    m_btnScan->setObjectName("btnPrimary");
    m_btnScan->setFixedWidth(88);
    connect(m_btnBrowse, &QPushButton::clicked, this, &CertScanPage::onBrowseFile);
    connect(m_btnScan,   &QPushButton::clicked, this, &CertScanPage::onStartScan);
    fileRow->addWidget(m_editPath, 1);
    fileRow->addWidget(m_btnBrowse);
    fileRow->addWidget(m_btnScan);
    m_mainLayout->addLayout(fileRow);

    QSplitter *sp = new QSplitter(Qt::Vertical);
    m_tblResults = new QTableWidget(0, 6);
    m_tblResults->setHorizontalHeaderLabels({"文件名","签名者","颁发机构","时间戳","签名状态","篡改检测"});
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
    m_txtDetail->setPlaceholderText("选择记录查看证书详情...");
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
        q.exec("SELECT file_name,signer,issuer,timestamp,sign_status,tamper_status FROM cert_scan ORDER BY id DESC LIMIT 100");
        while (q.next()) {
            int row = m_tblResults->rowCount(); m_tblResults->insertRow(row);
            m_tblResults->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));
            m_tblResults->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
            m_tblResults->setItem(row,2,new QTableWidgetItem(q.value(2).toString()));
            m_tblResults->setItem(row,3,new QTableWidgetItem(q.value(3).toString()));
            QString st = q.value(4).toString();
            QTableWidgetItem *si = new QTableWidgetItem(st);
            si->setForeground(st=="有效"?QColor("#4caf50"):QColor("#ef5350"));
            si->setTextAlignment(Qt::AlignCenter);
            m_tblResults->setItem(row,4,si);
            QString ts = q.value(5).toString();
            QTableWidgetItem *ti = new QTableWidgetItem(ts);
            ti->setForeground(ts=="未篡改"?QColor("#4caf50"):QColor("#ef5350"));
            ti->setTextAlignment(Qt::AlignCenter);
            m_tblResults->setItem(row,5,ti);
        }
    }
    if (m_tblResults->rowCount() == 0) {
        QList<QStringList> demo = {
            {"svchost32.exe","无签名","--","--","无签名","--"},
            {"explorer.exe","Microsoft Corporation","Microsoft Root CA","2025-11-01","有效","未篡改"},
            {"readme.pdf.exe","无签名","--","--","无签名","--"},
            {"update.exe","Unknown Publisher","--","--","证书过期","疑似篡改"},
        };
        for (const QStringList &d : demo) {
            int r = m_tblResults->rowCount(); m_tblResults->insertRow(r);
            for (int c = 0; c < d.size(); ++c) {
                QTableWidgetItem *it = new QTableWidgetItem(d[c]);
                if (c==4) it->setForeground(d[c]=="有效"?QColor("#4caf50"):QColor("#ef5350"));
                if (c==5) it->setForeground(d[c]=="未篡改"?QColor("#4caf50"):d[c]=="--"?QColor("#90caf9"):QColor("#ef5350"));
                it->setTextAlignment(c>=4?Qt::AlignCenter:Qt::AlignLeft|Qt::AlignVCenter);
                m_tblResults->setItem(r,c,it);
            }
        }
    }
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void CertScanPage::onBrowseFile() {
    QString p = QFileDialog::getOpenFileName(this,"选择文件","","所有文件 (*.*)");
    if (!p.isEmpty()) m_editPath->setText(p);
}
void CertScanPage::onStartScan() {
    m_lblStatus->setText("已提交证书验证：" + m_editPath->text());
    DatabaseManager::instance()->writeLog(m_role, m_username, "数字证书检测", m_editPath->text(), "success");
}
void CertScanPage::onRowSelected(int row, int) {
    m_txtDetail->setPlainText(
        "文件名：    " + (m_tblResults->item(row,0)?m_tblResults->item(row,0)->text():"--") + "\n"
        "签名者：    " + (m_tblResults->item(row,1)?m_tblResults->item(row,1)->text():"--") + "\n"
        "颁发机构：  " + (m_tblResults->item(row,2)?m_tblResults->item(row,2)->text():"--") + "\n"
        "时间戳：    " + (m_tblResults->item(row,3)?m_tblResults->item(row,3)->text():"--") + "\n"
        "签名状态：  " + (m_tblResults->item(row,4)?m_tblResults->item(row,4)->text():"--") + "\n"
        "篡改检测：  " + (m_tblResults->item(row,5)?m_tblResults->item(row,5)->text():"--") + "\n\n"
        "详细证书链：（待检测引擎填充）\n"
        "  根证书 → 中间证书 → 最终证书\n"
    );
}
