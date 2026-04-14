#pragma once
#ifndef PROCESSINFOPAGE_H
#define PROCESSINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
class ProcessInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit ProcessInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl;
};
#endif
