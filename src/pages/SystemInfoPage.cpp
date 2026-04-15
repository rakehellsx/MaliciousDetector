#include "pages/SystemInfoPage.h"
#include "ui_SystemInfoPage.h"

#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
SystemInfoPage::SystemInfoPage(QWidget *parent)
    : BasePage("\u7cfb\u7edf\u57fa\u672c\u4fe1\u606f", parent)
{
    ui = new Ui::SystemInfoPage();
    ui->setupUi(this);
    postSetupUi();
    m_tbl = ui->m_tbl;
    refreshData();
}

void SystemInfoPage::refreshData()
{
    m_tbl->setRowCount(0);
    auto rows = DatabaseManager::instance()->querySysInfo();
    for (const QVariant &_var : rows) { QVariantMap m = _var.toMap();
        int r = m_tbl->rowCount();
        m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["key"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["value"].toString()));
    }
    m_lblStatus->setText(QString("\u5171 %1 \u9879").arg(m_tbl->rowCount()));
}
