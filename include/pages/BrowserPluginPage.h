#pragma once
#ifndef BROWSERPLUGINPAGE_H
#define BROWSERPLUGINPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QComboBox>
#include <QLineEdit>
#include <QLabel>
namespace Ui { class BrowserPluginPage; }

class BrowserPluginPage : public BasePage {
    Q_OBJECT
public:
    explicit BrowserPluginPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onQuery();
private:
    Ui::BrowserPluginPage *ui{nullptr};
    void setupUi();
    void fillTable(const QVariantList &rows);
    QTableWidget *m_tbl{nullptr};
    QLineEdit    *m_edtKeyword{nullptr};
    QComboBox    *m_cmbBrowser{nullptr};
    QComboBox    *m_cmbRisk{nullptr};
    QLabel       *m_lblSummary{nullptr};
    QLabel       *m_lblStatus{nullptr};
};
#endif
