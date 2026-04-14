#pragma once
#ifndef MEMORYIMAGEPAGE_H
#define MEMORYIMAGEPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
class MemoryImagePage : public BasePage {
    Q_OBJECT
public:
    explicit MemoryImagePage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl;
};
#endif
