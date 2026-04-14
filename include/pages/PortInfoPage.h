#pragma once
#ifndef PORTINFOPAGE_H
#define PORTINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
class PortInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit PortInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl;
};
#endif
