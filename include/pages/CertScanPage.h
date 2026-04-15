#pragma once
#ifndef CERTSCANPAGE_H
#define CERTSCANPAGE_H
#include "pages/BasePage.h"
#include <QLineEdit>
#include <QTableWidget>
#include <QComboBox>
#include <QPushButton>
namespace Ui { class CertScanPage; }

class CertScanPage : public BasePage {
    Q_OBJECT
public:
    explicit CertScanPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onQuery();
    void onRowSelected(int row, int col);
private:
    Ui::CertScanPage *ui{nullptr};
    QLineEdit    *m_edtKeyword{nullptr};
    QComboBox    *m_cmbCertStatus{nullptr};
    QTableWidget *m_tbl{nullptr};
    void fillTable(const QVariantList &rows);
};
#endif
