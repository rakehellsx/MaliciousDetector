#pragma once
#ifndef AUTORUNPAGE_H
#define AUTORUNPAGE_H
#include "pages/BasePage.h"
#include <QTabWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
class AutorunPage : public BasePage {
    Q_OBJECT
public:
    explicit AutorunPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onQuery();
private:
    void setupUi();
    void fillTab(QTableWidget *tbl, const QString &type, const QString &kw, const QString &risk);
    QTabWidget   *m_tabs{nullptr};
    QTableWidget *m_tblReg{nullptr};
    QTableWidget *m_tblFolder{nullptr};
    QTableWidget *m_tblMenu{nullptr};
    QTableWidget *m_tblDebug{nullptr};
    QLineEdit    *m_edtKeyword{nullptr};
    QComboBox    *m_cmbRisk{nullptr};
    QLabel       *m_lblStatus{nullptr};
};
#endif
