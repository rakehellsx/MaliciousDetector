#pragma once
#ifndef BROWSERPLUGINPAGE_H
#define BROWSERPLUGINPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLabel>
#include <QComboBox>
#include <QJsonArray>

class BrowserPluginPage : public BasePage {
    Q_OBJECT
public:
    explicit BrowserPluginPage(QWidget *p = nullptr);
    void refreshData() override;

private slots:
    void filterByBrowser(int index);

private:
    void setupUi();
    void populateTable(const QJsonArray &plugins);

    QTableWidget *m_tbl;
    QLabel       *m_lblSummary;
    QComboBox    *m_cmbBrowser;
    QJsonArray    m_allPlugins;
};
#endif
