#include "pages/FileAssocPage.h"
#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QHeaderView>
#include <QLabel>
#include <QDateTime>
#include <QFont>

FileAssocPage::FileAssocPage(QWidget *parent)
    : BasePage("文件关联检测", parent)
{
    setupUi();
    refreshData();
}

void FileAssocPage::setupUi()
{
    QHBoxLayout *btnRow = new QHBoxLayout;
    btnRow->setContentsMargins(0,0,0,6);
    m_btnScan = new QPushButton("扫描文件关联");
    m_btnScan->setFixedWidth(120);
    m_btnScan->setStyleSheet("QPushButton{background:#1a3a6a;color:#fff;border:none;border-radius:3px;"
                             "padding:5px 12px;font-size:12px;}"
                             "QPushButton:hover{background:#245090;}");
    connect(m_btnScan, &QPushButton::clicked, this, &FileAssocPage::refreshData);
    m_lblSummary = new QLabel;
    m_lblSummary->setStyleSheet("font-size:11px;color:#8c8c8c;padding:0 8px;");
    btnRow->addWidget(m_btnScan);
    btnRow->addWidget(m_lblSummary);
    btnRow->addStretch();
    m_mainLayout->addLayout(btnRow);

    m_tbl = new QTableWidget(0, 5);
    m_tbl->setHorizontalHeaderLabels({"扩展名", "关联程序", "正常值", "当前值", "风险"});
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tbl->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_tbl->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_tbl->verticalHeader()->setVisible(false);
    m_tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tbl->setAlternatingRowColors(true);
    m_tbl->setStyleSheet(
        "QTableWidget{border:1px solid #d0d7e3;font-size:12px;}"
        "QHeaderView::section{background:#e8ecf4;padding:5px 8px;font-weight:600;border:1px solid #d0d7e3;}"
        "QTableWidget::item{padding:5px 8px;}"
        "QTableWidget::item:alternate{background:#fafbfd;}");
    m_mainLayout->addWidget(m_tbl, 1);
}

void FileAssocPage::refreshData()
{
    m_tbl->setRowCount(0);
    int highCount = 0, midCount = 0;

    QSqlDatabase db = QSqlDatabase::database("main_conn");
    bool loaded = false;
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.exec("SELECT ext,assoc_program,normal_value,current_value,risk_level FROM file_assoc_scan ORDER BY id DESC LIMIT 100");
        while (q.next()) {
            loaded = true;
            int row = m_tbl->rowCount(); m_tbl->insertRow(row);
            m_tbl->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));
            m_tbl->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
            QTableWidgetItem *ni = new QTableWidgetItem(q.value(2).toString());
            ni->setFont(QFont("Consolas",11));
            m_tbl->setItem(row,2,ni);
            QTableWidgetItem *ci = new QTableWidgetItem(q.value(3).toString());
            ci->setFont(QFont("Consolas",11));
            m_tbl->setItem(row,3,ci);
            QString risk = q.value(4).toString();
            if (risk == "high") { highCount++; }
            else if (risk == "medium") { midCount++; }
            QString riskText = (risk=="high")?"高危（已篡改）":(risk=="medium")?"注意":"正常";
            QTableWidgetItem *ri = new QTableWidgetItem(riskText);
            QFont rf = ri->font(); rf.setBold(true); ri->setFont(rf);
            if (risk=="high") {
                ri->setForeground(QColor("#f5222d"));
                for (int c=0;c<5;c++) if(m_tbl->item(row,c)) m_tbl->item(row,c)->setBackground(QColor("#fff1f0"));
                // 当前值与正常值不同时，当前值标红
                if (q.value(2).toString() != q.value(3).toString())
                    ci->setForeground(QColor("#f5222d"));
            } else if (risk=="medium") {
                ri->setForeground(QColor("#fa8c16"));
                for (int c=0;c<5;c++) if(m_tbl->item(row,c)) m_tbl->item(row,c)->setBackground(QColor("#fffbe6"));
            } else {
                ri->setForeground(QColor("#52c41a"));
            }
            m_tbl->setItem(row,4,ri);
        }
    }

    if (!loaded) {
        struct AssocDemo { QString ext,prog,normal,current,risk; };
        QList<AssocDemo> demo = {
            {".exe","应用程序",
             "exefile\\shell\\open\\command: \"%1\" %*",
             "exefile\\shell\\open\\command: \"C:\\Windows\\Temp\\svchost32.exe\" \"%1\" %*",
             "high"},
            {".txt","记事本",
             "txtfile\\shell\\open\\command: notepad.exe %1",
             "txtfile\\shell\\open\\command: notepad.exe %1",
             "low"},
            {".html","Chrome",
             "htmlfile\\shell\\open\\command: chrome.exe \"%1\"",
             "htmlfile\\shell\\open\\command: C:\\Windows\\Temp\\browser.exe \"%1\"",
             "medium"},
            {".pdf","Adobe Reader",
             "AcroExch.Document\\shell\\open\\command: AcroRd32.exe \"%1\"",
             "AcroExch.Document\\shell\\open\\command: AcroRd32.exe \"%1\"",
             "low"},
            {".doc","Word",
             "Word.Document.12\\shell\\Open\\command: WINWORD.EXE /n \"%1\"",
             "Word.Document.12\\shell\\Open\\command: C:\\Windows\\Temp\\payload.exe \"%1\"",
             "high"},
        };
        for (const auto &d : demo) {
            int r = m_tbl->rowCount(); m_tbl->insertRow(r);
            m_tbl->setItem(r,0,new QTableWidgetItem(d.ext));
            m_tbl->setItem(r,1,new QTableWidgetItem(d.prog));
            QTableWidgetItem *ni = new QTableWidgetItem(d.normal);
            ni->setFont(QFont("Consolas",11));
            m_tbl->setItem(r,2,ni);
            QTableWidgetItem *ci = new QTableWidgetItem(d.current);
            ci->setFont(QFont("Consolas",11));
            m_tbl->setItem(r,3,ci);
            QString riskText = (d.risk=="high")?"高危（已篡改）":(d.risk=="medium")?"注意":"正常";
            QTableWidgetItem *ri = new QTableWidgetItem(riskText);
            QFont rf = ri->font(); rf.setBold(true); ri->setFont(rf);
            if (d.risk=="high") {
                ri->setForeground(QColor("#f5222d"));
                highCount++;
                for (int c=0;c<5;c++) if(m_tbl->item(r,c)) m_tbl->item(r,c)->setBackground(QColor("#fff1f0"));
                if (d.normal != d.current) ci->setForeground(QColor("#f5222d"));
            } else if (d.risk=="medium") {
                ri->setForeground(QColor("#fa8c16"));
                midCount++;
                for (int c=0;c<5;c++) if(m_tbl->item(r,c)) m_tbl->item(r,c)->setBackground(QColor("#fffbe6"));
            } else {
                ri->setForeground(QColor("#52c41a"));
            }
            m_tbl->setItem(r,4,ri);
        }
    }

    QString summary = QString("共 %1 条").arg(m_tbl->rowCount());
    if (highCount > 0) summary += QString(" ｜ %1 条高危（已篡改）").arg(highCount);
    if (midCount > 0) summary += QString(" ｜ %1 条注意").arg(midCount);
    m_lblSummary->setText(summary);
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}
