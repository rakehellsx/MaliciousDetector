#pragma once
#ifndef SAMPLEEXTRACTPAGE_H
#define SAMPLEEXTRACTPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>

class SampleExtractPage : public BasePage {
    Q_OBJECT
public:
    explicit SampleExtractPage(QWidget *p = nullptr);
    void refreshData() override;

private slots:
    void onExtract();

private:
    void setupUi();
    QLineEdit    *m_editPath;
    QPushButton  *m_btnBrowse;
    QPushButton  *m_btnExtract;
    QTableWidget *m_tbl;
    QLabel       *m_lblSummary;
};
#endif
