#pragma once
#ifndef BROWSERPLUGINPAGE_H
#define BROWSERPLUGINPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QComboBox>
#include <QLabel>
#include <QVariantMap>
class BrowserPluginPage : public BasePage {
    Q_OBJECT
public:
    explicit BrowserPluginPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onBrowserFilter(int);
private:
    void setupUi();
    QTableWidget       *m_tbl{nullptr};
    QComboBox          *m_cmbBrowser{nullptr};
    QLabel             *m_lblSummary{nullptr};
    QLabel             *m_lblStatus{nullptr};
    QList<QVariantMap>  m_allPlugins;
};
#endif
