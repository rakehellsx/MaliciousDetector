#pragma once
#ifndef LOGAUDITPAGE_H
#define LOGAUDITPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QComboBox>
#include <QDateEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>

class LogAuditPage : public BasePage {
    Q_OBJECT
public:
    explicit LogAuditPage(QWidget *p=nullptr);
    void refreshData() override;

private slots:
    void onQuery();
    void onExport();

private:
    void setupUi();

    QComboBox    *m_cmbRole;
    QComboBox    *m_cmbType;
    QLineEdit    *m_edtUser;
    QDateEdit    *m_dateFrom;
    QDateEdit    *m_dateTo;
    QPushButton  *m_btnQuery;
    QPushButton  *m_btnExport;
    QTableWidget *m_tbl;
    QLabel       *m_lblCount;
};
#endif
