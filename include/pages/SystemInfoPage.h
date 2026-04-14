#pragma once
#ifndef SYSTEMINFOPAGE_H
#define SYSTEMINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLabel>
class SystemInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit SystemInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl;
};
#endif
