#pragma once
#ifndef DRIVERINFOPAGE_H
#define DRIVERINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QComboBox>
#include <QLineEdit>
#include <QLabel>
namespace Ui { class DriverInfoPage; }

class DriverInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit DriverInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onQuery();
private:
    Ui::DriverInfoPage *ui{nullptr};
    void loadDemoData();
    void fillTable(const QVariantList &rows);
    QTableWidget *m_tbl{nullptr};
    QLineEdit    *m_edtKeyword{nullptr};
    QComboBox    *m_cmbType{nullptr};
    QComboBox    *m_cmbSigned{nullptr};
    QComboBox    *m_cmbRisk{nullptr};
    QLabel       *m_lblSummary{nullptr};
    QLabel       *m_lblStatus{nullptr};
};
#endif
