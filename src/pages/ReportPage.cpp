#include "pages/ReportPage.h"
#include <QHBoxLayout>
#include <QSplitter>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QHeaderView>
#include <QFileDialog>
#include <QGroupBox>
#include <QLabel>

ReportPage::ReportPage(QWidget *parent) : BasePage("检测报告", parent) { setupUi(); refreshData(); }

void ReportPage::setupUi()
{
    // 工具栏
    QHBoxLayout *toolRow = new QHBoxLayout;
    QLabel *fmtLbl = new QLabel("导出格式：");
    fmtLbl->setObjectName("fieldLabel");
    m_cmbFormat = new QComboBox;
    m_cmbFormat->setObjectName("comboBox");
    m_cmbFormat->addItems({"Word (.docx)", "PDF (.pdf)", "HTML (.html)"});
    m_cmbFormat->setFixedWidth(160);
    m_btnGenerate = new QPushButton("生成报告");
    m_btnGenerate->setObjectName("btnPrimary");
    m_btnGenerate->setFixedWidth(100);
    m_btnExport = new QPushButton("导出报告");
    m_btnExport->setObjectName("btnSecondary");
    m_btnExport->setFixedWidth(100);
    connect(m_btnGenerate, &QPushButton::clicked, this, &ReportPage::onGenerateReport);
    connect(m_btnExport,   &QPushButton::clicked, this, &ReportPage::onExportReport);
    toolRow->addWidget(fmtLbl);
    toolRow->addWidget(m_cmbFormat);
    toolRow->addWidget(m_btnGenerate);
    toolRow->addWidget(m_btnExport);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    // 分割区：左侧汇总表 + 右侧报告预览
    QSplitter *sp = new QSplitter(Qt::Horizontal);

    // 左：威胁汇总表
    QWidget *leftWidget = new QWidget;
    QVBoxLayout *leftLay = new QVBoxLayout(leftWidget);
    leftLay->setContentsMargins(0,0,0,0);
    QLabel *sumLbl = new QLabel("威胁汇总");
    sumLbl->setObjectName("sectionLabel");
    leftLay->addWidget(sumLbl);
    m_tblSummary = new QTableWidget(0, 4);
    m_tblSummary->setHorizontalHeaderLabels({"威胁名称","类型","等级","处置建议"});
    styleTable(m_tblSummary);
    m_tblSummary->setColumnWidth(0, 180);
    m_tblSummary->setColumnWidth(1, 100);
    m_tblSummary->setColumnWidth(2, 60);
    connect(m_tblSummary, &QTableWidget::cellClicked, this, &ReportPage::onRowSelected);
    leftLay->addWidget(m_tblSummary, 1);
    sp->addWidget(leftWidget);

    // 右：报告预览
    QWidget *rightWidget = new QWidget;
    QVBoxLayout *rightLay = new QVBoxLayout(rightWidget);
    rightLay->setContentsMargins(0,0,0,0);
    QLabel *prevLbl = new QLabel("报告预览");
    prevLbl->setObjectName("sectionLabel");
    rightLay->addWidget(prevLbl);
    m_txtReport = new QTextEdit;
    m_txtReport->setReadOnly(true);
    m_txtReport->setObjectName("reportView");
    m_txtReport->setPlaceholderText("点击「生成报告」生成检测报告预览...");
    rightLay->addWidget(m_txtReport, 1);
    sp->addWidget(rightWidget);
    sp->setStretchFactor(0, 1);
    sp->setStretchFactor(1, 2);
    m_mainLayout->addWidget(sp, 1);
}

void ReportPage::refreshData()
{
    m_tblSummary->setRowCount(0);
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.exec("SELECT conclusion,file_type,risk_level FROM static_scan WHERE risk_level IN ('high','medium','low') ORDER BY id DESC LIMIT 50");
        while (q.next()) {
            int row = m_tblSummary->rowCount(); m_tblSummary->insertRow(row);
            m_tblSummary->setItem(row,0,new QTableWidgetItem(q.value(0).toString()));
            m_tblSummary->setItem(row,1,new QTableWidgetItem(q.value(1).toString()));
            QString risk = q.value(2).toString();
            QTableWidgetItem *ri = new QTableWidgetItem(risk=="high"?"高危":risk=="medium"?"中危":"低危");
            ri->setForeground(risk=="high"?QColor("#ef5350"):risk=="medium"?QColor("#ff9800"):QColor("#42a5f5"));
            ri->setTextAlignment(Qt::AlignCenter);
            m_tblSummary->setItem(row,2,ri);
            m_tblSummary->setItem(row,3,new QTableWidgetItem("建议隔离并清除"));
        }
    }
    if (m_tblSummary->rowCount() == 0) {
        QList<QStringList> demo = {
            {"Trojan.Win32.Agent.abc","木马","高危","立即隔离，阻止执行"},
            {"Backdoor.Generic.Dropper","后门","高危","立即隔离，检查网络连接"},
            {"Worm.AutoRun.Spread","蠕虫","高危","隔离，检查所有移动存储"},
            {"Spyware.KeyLogger","间谍软件","中危","隔离，更改所有密码"},
            {"Adware.BrowserHijack","广告软件","低危","清除浏览器插件"},
        };
        for (const QStringList &d : demo) {
            int r = m_tblSummary->rowCount(); m_tblSummary->insertRow(r);
            for (int c = 0; c < d.size(); ++c) {
                QTableWidgetItem *it = new QTableWidgetItem(d[c]);
                if (c==2) {
                    it->setForeground(d[c]=="高危"?QColor("#ef5350"):d[c]=="中危"?QColor("#ff9800"):QColor("#42a5f5"));
                    it->setTextAlignment(Qt::AlignCenter);
                }
                m_tblSummary->setItem(r,c,it);
            }
        }
    }
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void ReportPage::onGenerateReport()
{
    QString now = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    QString report;
    report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    report += "          恶意代码辅助检测系统  检测报告\n";
    report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
    report += "报告生成时间：" + now + "\n";
    report += "检测主机：    SECURE-PC-001\n";
    report += "操作系统：    Windows 10 专业版 64位\n";
    report += "产品版本：    V3.0.20251120\n";
    report += "病毒库版本：  " + DatabaseManager::instance()->getSetting("virus_db_version","20251120") + "\n\n";
    report += "━━ 检测结论 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

    int high=0, med=0, low=0;
    for (int r = 0; r < m_tblSummary->rowCount(); ++r) {
        QString risk = m_tblSummary->item(r,2) ? m_tblSummary->item(r,2)->text() : "";
        if (risk=="高危") high++;
        else if (risk=="中危") med++;
        else if (risk=="低危") low++;
    }
    report += QString("  高危威胁：%1 项\n  中危威胁：%2 项\n  低危威胁：%3 项\n\n").arg(high).arg(med).arg(low);

    report += "━━ 威胁详情 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
    for (int r = 0; r < m_tblSummary->rowCount(); ++r) {
        report += QString("[%1] %2 (%3)\n").arg(r+1)
            .arg(m_tblSummary->item(r,0)?m_tblSummary->item(r,0)->text():"")
            .arg(m_tblSummary->item(r,2)?m_tblSummary->item(r,2)->text():"");
        report += "  类型：" + (m_tblSummary->item(r,1)?m_tblSummary->item(r,1)->text():"") + "\n";
        report += "  处置建议：" + (m_tblSummary->item(r,3)?m_tblSummary->item(r,3)->text():"") + "\n\n";
    }
    report += "━━ 处置建议 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
    report += "1. 立即隔离所有高危威胁文件，阻止其执行；\n";
    report += "2. 检查并清理注册表自启动项；\n";
    report += "3. 检查网络连接，阻断可疑外联IP；\n";
    report += "4. 更新系统补丁和病毒库；\n";
    report += "5. 对受影响账户更改密码；\n";
    report += "6. 建议进行全盘深度扫描。\n\n";
    report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    report += "本报告由恶意代码辅助检测系统自动生成，仅供参考。\n";

    m_txtReport->setPlainText(report);
    DatabaseManager::instance()->writeLog(m_role, m_username, "生成报告", "生成检测报告", "success");
    m_lblStatus->setText("报告已生成");
}

void ReportPage::onExportReport()
{
    if (m_txtReport->toPlainText().isEmpty()) { onGenerateReport(); }
    QString fmt = m_cmbFormat->currentText();
    QString filter = fmt.contains("docx") ? "Word文档 (*.docx)" :
                     fmt.contains("pdf")  ? "PDF文件 (*.pdf)" : "HTML文件 (*.html)";
    QString path = QFileDialog::getSaveFileName(this, "导出报告", "检测报告_" +
        QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss"), filter);
    if (!path.isEmpty()) {
        QFile f(path);
        if (f.open(QIODevice::WriteOnly|QIODevice::Text)) {
            QTextStream ts(&f);
            ts.setCodec("UTF-8");
            if (fmt.contains("html")) {
                ts << "<html><head><meta charset='utf-8'><title>检测报告</title></head><body><pre>"
                   << m_txtReport->toPlainText().toHtmlEscaped()
                   << "</pre></body></html>";
            } else {
                ts << m_txtReport->toPlainText();
            }
            f.close();
            DatabaseManager::instance()->writeLog(m_role, m_username, "导出报告", path, "success");
            m_lblStatus->setText("已导出：" + path);
        }
    }
}

void ReportPage::onRowSelected(int row, int)
{
    if (!m_tblSummary->item(row,0)) return;
    m_txtReport->setPlainText(
        "威胁名称：" + m_tblSummary->item(row,0)->text() + "\n"
        "威胁类型：" + (m_tblSummary->item(row,1)?m_tblSummary->item(row,1)->text():"") + "\n"
        "风险等级：" + (m_tblSummary->item(row,2)?m_tblSummary->item(row,2)->text():"") + "\n"
        "处置建议：" + (m_tblSummary->item(row,3)?m_tblSummary->item(row,3)->text():"") + "\n\n"
        "详细描述：（待检测引擎填充）\n"
    );
}
