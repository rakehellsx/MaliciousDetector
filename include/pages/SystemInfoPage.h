#pragma once
#ifndef SYSTEMINFOPAGE_H
#define SYSTEMINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLabel>
namespace Ui { class SystemInfoPage; }

class SystemInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit SystemInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    Ui::SystemInfoPage *ui{nullptr};
    void setupUi();
    QTableWidget *m_tbl;
};
#endif
