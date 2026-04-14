#pragma once
#ifndef SHAREDRESOURCEPAGE_H
#define SHAREDRESOURCEPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
class SharedResourcePage : public BasePage {
    Q_OBJECT
public:
    explicit SharedResourcePage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onQuery();
private:
    void setupUi();
    void fillTable(const QVariantList &rows);
    QTableWidget *m_tbl{nullptr};
    QLineEdit    *m_edtKeyword{nullptr};
    QComboBox    *m_cmbRisk{nullptr};
    QLabel       *m_lblStatus{nullptr};
};
#endif
