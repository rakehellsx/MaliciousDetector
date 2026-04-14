#include "pages/ReportPage.h"
#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QFrame>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QTextEdit>
#include <QHeaderView>
#include <QSqlQuery>
#include <QDateTime>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QMessageBox>
#include <QFont>
#include <QGroupBox>

ReportPage::ReportPage(QWidget *parent) : BasePage("检测报告", parent) {
    setupUi();
    refreshData();
}

void ReportPage::setupUi() {
    // 顶部工具栏
    m_btnGenerate   = new QPushButton("生成报告");
    m_btnExportDoc  = new QPushButton("导出 DOC");
    m_btnExportPdf  = new QPushButton("导出 PDF");
    m_btnExportHtml = new QPushButton("导出 HTML");

    m_btnGenerate->setObjectName("btnPrimary");
    m_btnExportDoc->setObjectName("btnSecondary");
    m_btnExportPdf->setObjectName("btnSecondary");
    m_btnExportHtml->setObjectName("btnSecondary");

    connect(m_btnGenerate,   &QPushButton::clicked, this, &ReportPage::onGenerateReport);
    connect(m_btnExportDoc,  &QPushButton::clicked, this, &ReportPage::onExportDoc);
    connect(m_btnExportPdf,  &QPushButton::clicked, this, &ReportPage::onExportPdf);
    connect(m_btnExportHtml, &QPushButton::clicked, this, &ReportPage::onExportHtml);

    QHBoxLayout *toolRow = new QHBoxLayout;
    toolRow->addWidget(m_btnGenerate);
    toolRow->addWidget(m_btnExportDoc);
    toolRow->addWidget(m_btnExportPdf);
    toolRow->addWidget(m_btnExportHtml);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    // 分隔线
    QFrame *divider = new QFrame;
    divider->setFrameShape(QFrame::HLine);
    divider->setStyleSheet("color:#d0d7e3;margin:4px 0;");
    m_mainLayout->addWidget(divider);

    // 报告标题
    QLabel *lblTitle = new QLabel("恶意代码辅助检测分析报告");
    QFont tf = lblTitle->font(); tf.setPointSize(14); tf.setBold(true);
    lblTitle->setFont(tf);
    lblTitle->setAlignment(Qt::AlignCenter);
    lblTitle->setStyleSheet("color:#1a3a6a;margin:6px 0;");
    m_mainLayout->addWidget(lblTitle);

    // 报告元信息
    QLabel *lblMeta = new QLabel(
        QString("检测时间：%1   主机名：SECURE-PC-001   操作系统：Windows 10 专业版 64位   报告编号：RPT-%2-001")
        .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"))
        .arg(QDateTime::currentDateTime().toString("yyyyMMdd"))
    );
    lblMeta->setStyleSheet("font-size:11px;color:#888;margin-bottom:8px;");
    lblMeta->setAlignment(Qt::AlignCenter);
    m_mainLayout->addWidget(lblMeta);

    // 一、风险等级汇总
    QLabel *lblSec1 = new QLabel("一、风险等级汇总");
    lblSec1->setStyleSheet("font-weight:bold;font-size:12px;color:#333;margin-top:4px;");
    m_mainLayout->addWidget(lblSec1);

    // 风险卡片
    auto makeCard = [](const QString &title, const QString &numColor,
                       const QString &bgColor, const QString &borderColor) -> QPair<QFrame*, QLabel*> {
        QFrame *card = new QFrame;
        card->setFrameShape(QFrame::Box);
        card->setStyleSheet(QString("QFrame{background:%1;border-radius:4px;border:1px solid %2;}")
                            .arg(bgColor, borderColor));
        card->setMinimumWidth(110);
        card->setMaximumWidth(160);
        QVBoxLayout *cl = new QVBoxLayout(card);
        cl->setContentsMargins(12, 8, 12, 8);
        QLabel *numLbl = new QLabel("0");
        numLbl->setAlignment(Qt::AlignCenter);
        QFont f = numLbl->font(); f.setPointSize(22); f.setBold(true); numLbl->setFont(f);
        numLbl->setStyleSheet(QString("color:%1;").arg(numColor));
        QLabel *titleLbl = new QLabel(title);
        titleLbl->setAlignment(Qt::AlignCenter);
        titleLbl->setStyleSheet("font-size:12px;color:#555;");
        cl->addWidget(numLbl);
        cl->addWidget(titleLbl);
        return {card, numLbl};
    };

    auto [cardHigh,     numHigh]     = makeCard("高危威胁", "#cf1322", "#fff1f0", "#ffccc7");
    auto [cardMedium,   numMedium]   = makeCard("中危威胁", "#d46b08", "#fff7e6", "#ffd591");
    auto [cardLow,      numLow]      = makeCard("低危威胁", "#096dd9", "#e6f7ff", "#91d5ff");
    auto [cardIsolated, numIsolated] = makeCard("已隔离",   "#389e0d", "#f6ffed", "#b7eb8f");

    m_lblHigh     = numHigh;
    m_lblMedium   = numMedium;
    m_lblLow      = numLow;
    m_lblIsolated = numIsolated;

    QHBoxLayout *cardRow = new QHBoxLayout;
    cardRow->addWidget(cardHigh);
    cardRow->addWidget(cardMedium);
    cardRow->addWidget(cardLow);
    cardRow->addWidget(cardIsolated);
    cardRow->addStretch();
    m_mainLayout->addLayout(cardRow);

    // 二、威胁列表
    QLabel *lblSec2 = new QLabel("二、恶意代码检测结果");
    lblSec2->setStyleSheet("font-weight:bold;font-size:12px;color:#333;margin-top:10px;");
    m_mainLayout->addWidget(lblSec2);

    m_tblThreats = new QTableWidget(0, 6);
    m_tblThreats->setHorizontalHeaderLabels({"威胁名称","危险等级","恶意类型","文件路径","发现时间","状态"});
    styleTable(m_tblThreats);
    m_tblThreats->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_tblThreats->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_tblThreats->setColumnWidth(1, 70);
    m_tblThreats->setColumnWidth(2, 80);
    m_tblThreats->setColumnWidth(4, 140);
    m_tblThreats->setColumnWidth(5, 70);
    m_tblThreats->setMaximumHeight(180);
    m_mainLayout->addWidget(m_tblThreats);

    // 三、处置建议
    QLabel *lblSec3 = new QLabel("三、处置建议");
    lblSec3->setStyleSheet("font-weight:bold;font-size:12px;color:#333;margin-top:10px;");
    m_mainLayout->addWidget(lblSec3);

    m_txtReport = new QTextEdit;
    m_txtReport->setReadOnly(true);
    m_txtReport->setObjectName("reportView");
    m_mainLayout->addWidget(m_txtReport, 1);
}

void ReportPage::refreshData() {
    m_tblThreats->setRowCount(0);
    int high = 0, medium = 0, low = 0, isolated = 0;

    QSqlQuery q;
    q.exec("SELECT file_name, virus_name, file_type, risk_level, scan_time, conclusion FROM static_scan ORDER BY scan_time DESC");
    while (q.next()) {
        QString fileName   = q.value(0).toString();
        QString virusName  = q.value(1).toString();
        QString fileType   = q.value(2).toString();
        QString riskLevel  = q.value(3).toString();
        QString scanTime   = q.value(4).toString();
        QString conclusion = q.value(5).toString();

        if (riskLevel == "高危") high++;
        else if (riskLevel == "中危") medium++;
        else if (riskLevel == "低危") low++;
        if (conclusion.contains("隔离")) isolated++;

        int row = m_tblThreats->rowCount();
        m_tblThreats->insertRow(row);

        QString threatName = virusName.isEmpty() ? fileName : virusName;
        m_tblThreats->setItem(row, 0, new QTableWidgetItem(threatName));

        QTableWidgetItem *lvlItem = new QTableWidgetItem(riskLevel);
        if (riskLevel == "高危")      lvlItem->setForeground(QColor("#cf1322"));
        else if (riskLevel == "中危") lvlItem->setForeground(QColor("#d46b08"));
        else if (riskLevel == "低危") lvlItem->setForeground(QColor("#096dd9"));
        else                          lvlItem->setForeground(QColor("#389e0d"));
        m_tblThreats->setItem(row, 1, lvlItem);
        m_tblThreats->setItem(row, 2, new QTableWidgetItem(fileType));
        m_tblThreats->setItem(row, 3, new QTableWidgetItem(fileName));
        m_tblThreats->setItem(row, 4, new QTableWidgetItem(scanTime));

        QString status = conclusion.contains("隔离") ? "已隔离" : "待处理";
        QTableWidgetItem *stItem = new QTableWidgetItem(status);
        stItem->setForeground(status == "已隔离" ? QColor("#389e0d") : QColor("#d46b08"));
        m_tblThreats->setItem(row, 5, stItem);

        if (riskLevel == "高危")
            for (int c = 0; c < 6; c++)
                if (m_tblThreats->item(row,c)) m_tblThreats->item(row,c)->setBackground(QColor("#fff1f0"));
    }

    m_lblHigh->setText(QString::number(high));
    m_lblMedium->setText(QString::number(medium));
    m_lblLow->setText(QString::number(low));
    m_lblIsolated->setText(QString::number(isolated));

    // 处置建议：从数据库读取
    QString advice = DatabaseManager::instance()->getSetting("report_advice", "");
    if (advice.isEmpty() && m_tblThreats->rowCount() > 0) {
        advice = "请根据检测结果对各威胁文件进行隔离或删除处置，并更新病毒库后重新扫描。";
    } else if (advice.isEmpty()) {
        advice = "未检测到威胁，系统安全。";
    }
    m_txtReport->setPlainText(advice);

    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void ReportPage::onGenerateReport() {
    refreshData();
    DatabaseManager::instance()->writeLog(m_role, m_username, "生成检测报告", "生成检测报告", "success");
    m_lblStatus->setText("报告已生成");
}

void ReportPage::onExportDoc() {
    QString path = QFileDialog::getSaveFileName(this, "导出 DOC 报告",
        "检测报告_" + QDateTime::currentDateTime().toString("yyyyMMdd") + ".txt",
        "文档文件 (*.txt)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream ts(&f);
        ts.setCodec("UTF-8");
        ts << "恶意代码辅助检测分析报告\n";
        ts << "========================\n";
        ts << "检测时间：" << QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") << "\n\n";
        ts << "三、处置建议\n" << m_txtReport->toPlainText();
        f.close();
        QMessageBox::information(this, "导出成功", "DOC 报告已保存至：" + path);
        DatabaseManager::instance()->writeLog(m_role, m_username, "导出DOC报告", path, "success");
    }
}

void ReportPage::onExportPdf() {
    QMessageBox::information(this, "导出 PDF", "PDF 导出功能需要 Qt PrintSupport 模块，当前版本暂不支持。");
}

void ReportPage::onExportHtml() {
    QString path = QFileDialog::getSaveFileName(this, "导出 HTML 报告",
        "检测报告_" + QDateTime::currentDateTime().toString("yyyyMMdd") + ".html",
        "HTML文件 (*.html)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream ts(&f);
        ts.setCodec("UTF-8");
        ts << "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>检测报告</title>";
        ts << "<style>body{font-family:SimHei,Arial;font-size:13px;padding:20px;}";
        ts << "h1{color:#1a3a6a;text-align:center;}";
        ts << "table{border-collapse:collapse;width:100%;margin:10px 0;}";
        ts << "th,td{border:1px solid #d0d7e3;padding:6px 10px;}th{background:#f5f7fa;}</style></head><body>";
        ts << "<h1>恶意代码辅助检测分析报告</h1>";
        ts << "<p style='text-align:center;color:#888;'>检测时间：" << QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") << "</p>";
        ts << "<h3>二、恶意代码检测结果</h3><table>";
        ts << "<tr><th>威胁名称</th><th>危险等级</th><th>恶意类型</th><th>文件路径</th><th>发现时间</th><th>状态</th></tr>";
        for (int r = 0; r < m_tblThreats->rowCount(); r++) {
            ts << "<tr>";
            for (int c = 0; c < 6; c++)
                ts << "<td>" << (m_tblThreats->item(r,c) ? m_tblThreats->item(r,c)->text().toHtmlEscaped() : "") << "</td>";
            ts << "</tr>";
        }
        ts << "</table><h3>三、处置建议</h3><pre style='background:#f5f7fa;padding:12px;border:1px solid #d0d7e3;'>"
           << m_txtReport->toPlainText().toHtmlEscaped() << "</pre>";
        ts << "</body></html>";
        f.close();
        QMessageBox::information(this, "导出成功", "HTML 报告已保存至：" + path);
        DatabaseManager::instance()->writeLog(m_role, m_username, "导出HTML报告", path, "success");
    }
}
