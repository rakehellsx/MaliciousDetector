#pragma once
#ifndef FILEASSOCPAGE_H
#define FILEASSOCPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>

class FileAssocPage : public BasePage {
    Q_OBJECT
public:
    explicit FileAssocPage(QWidget *p = nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl;
    QPushButton  *m_btnScan;
    QLabel       *m_lblSummary;
};
#endif
