#pragma once
#ifndef REPORTPAGE_H
#define REPORTPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QComboBox>
class ReportPage : public BasePage {
    Q_OBJECT
public:
    explicit ReportPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onGenerateReport();
    void onExportReport();
    void onRowSelected(int row, int col);
private:
    void setupUi();
    QComboBox    *m_cmbFormat;
    QPushButton  *m_btnGenerate;
    QPushButton  *m_btnExport;
    QTableWidget *m_tblSummary;
    QTextEdit    *m_txtReport;
};
#endif
