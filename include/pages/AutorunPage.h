#pragma once
#ifndef AUTORUNPAGE_H
#define AUTORUNPAGE_H
#include "pages/BasePage.h"
#include <QTabWidget>
#include <QTableWidget>
#include <QLabel>
class AutorunPage : public BasePage {
    Q_OBJECT
public:
    explicit AutorunPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTabWidget   *m_tabs{nullptr};
    QTableWidget *m_tblReg{nullptr};
    QTableWidget *m_tblFolder{nullptr};
    QTableWidget *m_tblMenu{nullptr};
    QTableWidget *m_tblDebug{nullptr};
    QLabel       *m_lblStatus{nullptr};
};
#endif
