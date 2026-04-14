#pragma once
#ifndef FILEASSOCPAGE_H
#define FILEASSOCPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QPushButton>
class FileAssocPage : public BasePage {
    Q_OBJECT
public:
    explicit FileAssocPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl;
    QPushButton  *m_btnScan;
};
#endif
