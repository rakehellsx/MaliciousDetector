#pragma once
#ifndef NETWORKINFOPAGE_H
#define NETWORKINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
class NetworkInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit NetworkInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl;
};
#endif
