#pragma once
#ifndef SCHEDULEDTASKPAGE_H
#define SCHEDULEDTASKPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
class ScheduledTaskPage : public BasePage {
    Q_OBJECT
public:
    explicit ScheduledTaskPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl;
};
#endif
