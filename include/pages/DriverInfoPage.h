#pragma once
#ifndef DRIVERINFOPAGE_H
#define DRIVERINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLabel>
#include <QComboBox>
#include <QJsonArray>

class DriverInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit DriverInfoPage(QWidget *p = nullptr);
    void refreshData() override;

private slots:
    void filterByType(int index);

private:
    void setupUi();
    void populateTable(const QJsonArray &drivers);

    QTableWidget *m_tbl;
    QLabel       *m_lblSummary;
    QComboBox    *m_cmbType;
    QJsonArray    m_allDrivers;
};
#endif
