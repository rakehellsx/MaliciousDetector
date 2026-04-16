#pragma once
#ifndef VULNDETECTPAGE_H
#define VULNDETECTPAGE_H

#include "pages/BasePage.h"
#include <QTableWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QList>
#include <QVariantMap>

namespace Ui { class VulnDetectPage; }

class VulnDetectPage : public BasePage {
    Q_OBJECT
public:
    explicit VulnDetectPage(QWidget *parent = nullptr);
    ~VulnDetectPage();
    void refreshData() override;

private slots:
    void onQuery();
    void onExport();

private:
    void loadData();
    void showDetailDialog(const QVariantMap &rec);

    Ui::VulnDetectPage *ui{nullptr};

    QLineEdit    *m_edtSearch{nullptr};
    QComboBox    *m_cmbRisk{nullptr};
    QComboBox    *m_cmbProto{nullptr};
    QPushButton  *m_btnQuery{nullptr};
    QPushButton  *m_btnExport{nullptr};
    QTableWidget *m_tblVuln{nullptr};

    QList<QVariantMap> m_dataCache;
};

#endif // VULNDETECTPAGE_H
