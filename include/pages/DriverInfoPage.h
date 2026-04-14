#pragma once
#ifndef DRIVERINFOPAGE_H
#define DRIVERINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QComboBox>
#include <QLabel>
#include <QVariantMap>
class DriverInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit DriverInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onTypeFilter(int);
private:
    void setupUi();
    QTableWidget       *m_tbl{nullptr};
    QComboBox          *m_cmbType{nullptr};
    QLabel             *m_lblSummary{nullptr};
    QLabel             *m_lblStatus{nullptr};
    QList<QVariantMap>  m_allDrivers;
};
#endif
