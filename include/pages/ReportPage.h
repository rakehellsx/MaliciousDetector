#pragma once
#ifndef REPORTPAGE_H
#define REPORTPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>

class ReportPage : public BasePage {
    Q_OBJECT
public:
    explicit ReportPage(QWidget *p=nullptr);
    void refreshData() override;

private slots:
    void onGenerateReport();
    void onExportDoc();
    void onExportPdf();
    void onExportHtml();

private:
    void setupUi();
    void buildReportPreview();

    // 风险汇总卡片标签
    QLabel       *m_lblHigh;
    QLabel       *m_lblMedium;
    QLabel       *m_lblLow;
    QLabel       *m_lblIsolated;

    // 威胁列表
    QTableWidget *m_tblThreats;

    // 报告预览
    QTextEdit    *m_txtReport;

    // 按钮
    QPushButton  *m_btnGenerate;
    QPushButton  *m_btnExportDoc;
    QPushButton  *m_btnExportPdf;
    QPushButton  *m_btnExportHtml;
};
#endif
