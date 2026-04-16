#pragma once
#ifndef SAMPLEEXTRACTPAGE_H
#define SAMPLEEXTRACTPAGE_H
#include "pages/BasePage.h"
#include <QComboBox>
#include <QTableWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>

namespace Ui { class SampleExtractPage; }

class SampleExtractPage : public BasePage {
    Q_OBJECT
public:
    explicit SampleExtractPage(QWidget *p = nullptr);
    void refreshData() override;

private slots:
    void onExtract();
    void onQuery();

private:
    Ui::SampleExtractPage *ui{nullptr};
    void setupUi();
    void fillTable(const QVariantList &rows);
    QVariantList loadDemoData();
    QLineEdit    *m_editPath{nullptr};
    QPushButton  *m_btnBrowse{nullptr};
    QPushButton  *m_btnExtract{nullptr};
    QTableWidget *m_tbl{nullptr};
    QLineEdit    *m_edtKeyword{nullptr};
    QComboBox    *m_cmbType{nullptr};
    QLabel       *m_lblSummary{nullptr};
    QLabel       *m_lblStatus{nullptr};
};
#endif
