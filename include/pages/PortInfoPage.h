#pragma once
#ifndef PORTINFOPAGE_H
#define PORTINFOPAGE_H
#include "pages/BasePage.h"
#include <QTableWidget>
#include <QComboBox>
#include <QLabel>
#include <QVariantMap>
class PortInfoPage : public BasePage {
    Q_OBJECT
public:
    explicit PortInfoPage(QWidget *p=nullptr);
    void refreshData() override;
private slots:
    void onProtoFilter(int);
private:
    void setupUi();
    QTableWidget       *m_tbl{nullptr};
    QComboBox          *m_cmbProto{nullptr};
    QLabel             *m_lblStatus{nullptr};
    QList<QVariantMap>  m_allRows;
};
#endif
