#pragma once
#ifndef AUTORUNPAGE_H
#define AUTORUNPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
class AutorunPage : public BasePage {
    Q_OBJECT
public:
    explicit AutorunPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl;
};
#endif
