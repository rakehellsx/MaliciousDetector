#pragma once
#ifndef DISKINFOPAGE_H
#define DISKINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
class DiskInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit DiskInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl;
};
#endif
