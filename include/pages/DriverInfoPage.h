#pragma once
#ifndef DRIVERINFOPAGE_H
#define DRIVERINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
class DriverInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit DriverInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl;
};
#endif
