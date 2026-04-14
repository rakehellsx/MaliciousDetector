#pragma once
#ifndef REPORTPAGE_H
#define REPORTPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QComboBox>
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
    void onQueryThreats();

private:
    void setupUi();
    void buildReportPreview();
    void fillThreats(const QVariantList &rows);

    // 风险汇总卡片标签
    QLabel       *m_lblHigh{nullptr};
    QLabel       *m_lblMedium{nullptr};
    QLabel       *m_lblLow{nullptr};
    QLabel       *m_lblIsolated{nullptr};

    // 威胁列表查询栏
    QLineEdit    *m_edtThreatKw{nullptr};
    QComboBox    *m_cmbThreatRisk{nullptr};

    // 威胁列表
    QTableWidget *m_tblThreats{nullptr};

    // 报告预览
    QTextEdit    *m_txtReport{nullptr};

    // 按钮
    QPushButton  *m_btnGenerate{nullptr};
    QPushButton  *m_btnExportDoc{nullptr};
    QPushButton  *m_btnExportPdf{nullptr};
    QPushButton  *m_btnExportHtml{nullptr};
};
#endif
