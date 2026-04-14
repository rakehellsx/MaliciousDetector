#pragma once
#ifndef CERTSCANPAGE_H
#define CERTSCANPAGE_H
#include "pages/BasePage.h"
#include <QLineEdit>
#include <QTableWidget>
#include <QTextEdit>
#include <QPushButton>
class CertScanPage : public BasePage {
    Q_OBJECT
public:
    explicit CertScanPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onBrowseFile();
    void onStartScan();
    void onRowSelected(int row, int col);
private:
    void setupUi();
    QLineEdit    *m_editPath;
    QPushButton  *m_btnBrowse;
    QPushButton  *m_btnScan;
    QTableWidget *m_tblResults;
    QTextEdit    *m_txtDetail;
};
#endif
