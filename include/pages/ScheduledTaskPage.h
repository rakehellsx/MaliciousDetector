#pragma once
#ifndef SCHEDULEDTASKPAGE_H
#define SCHEDULEDTASKPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLabel>
class ScheduledTaskPage : public BasePage {
    Q_OBJECT
public:
    explicit ScheduledTaskPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl{nullptr};
    QLabel       *m_lblSummary{nullptr};
    QLabel       *m_lblStatus{nullptr};
};
#endif
