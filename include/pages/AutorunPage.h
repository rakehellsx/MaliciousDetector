#pragma once
#ifndef AUTORUNPAGE_H
#define AUTORUNPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QTabWidget>
#include <QLabel>

class AutorunPage : public BasePage {
    Q_OBJECT
public:
    explicit AutorunPage(QWidget *p = nullptr);
    void refreshData() override;

private:
    void setupUi();
    void populateRegTab(const QJsonArray &items);
    void populateFolderTab(const QJsonArray &items);
    void populateRightClickTab(const QJsonArray &items);
    void populateDebuggerTab(const QJsonArray &items);

    QTabWidget   *m_tabs;
    QTableWidget *m_tblReg;
    QTableWidget *m_tblFolder;
    QTableWidget *m_tblRightClick;
    QTableWidget *m_tblDebugger;
    QLabel       *m_lblRegSummary;
};
#endif
