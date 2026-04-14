#pragma once
#ifndef SHAREDRESOURCEPAGE_H
#define SHAREDRESOURCEPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLabel>
class SharedResourcePage : public BasePage {
    Q_OBJECT
public:
    explicit SharedResourcePage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl{nullptr};
    QLabel       *m_lblStatus{nullptr};
};
#endif
