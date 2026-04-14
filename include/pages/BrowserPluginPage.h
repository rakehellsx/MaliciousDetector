#pragma once
#ifndef BROWSERPLUGINPAGE_H
#define BROWSERPLUGINPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
class BrowserPluginPage : public BasePage {
    Q_OBJECT
public:
    explicit BrowserPluginPage(QWidget *p=nullptr);
    void refreshData() override;
private:
    void setupUi();
    QTableWidget *m_tbl;
};
#endif
