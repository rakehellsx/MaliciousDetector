#include "pages/SharedResourcePage.h"
#include "ui_SharedResourcePage.h"
#include "DatabaseManager.h"
#include <QTableWidgetItem>
#include <QPushButton>
#include <QColor>
#include <QHeaderView>

SharedResourcePage::SharedResourcePage(QWidget *parent)
    : BasePage("共享资源", parent)
{
    ui = new Ui::SharedResourcePage();
    ui->setupUi(this);
    postSetupUi();
    m_tbl        = ui->m_tbl;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbRisk    = ui->m_cmbRisk;
    m_lblStatus  = ui->m_lblStatus;

    m_tbl->horizontalHeader()->setStretchLastSection(true);
    m_tbl->verticalHeader()->setVisible(false);
    m_tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tbl->setAlternatingRowColors(true);

    connect(ui->btnQuery,   &QPushButton::clicked, this, &SharedResourcePage::onQuery);
    connect(ui->btnRefresh, &QPushButton::clicked, this, &SharedResourcePage::refreshData);
    connect(ui->btnExport,  &QPushButton::clicked, this, [this]{ m_lblStatus->setText("导出功能开发中..."); });

    refreshData();
}

void SharedResourcePage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbRisk->setCurrentIndex(0);
    onQuery();
}

void SharedResourcePage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     riskIdx = m_cmbRisk->currentIndex();
    QStringList riskMap = {"", "高危", "中危", "低危", "正常"};
    QString riskFilter = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";

    auto rows = DatabaseManager::instance()->execSelect(
        "SELECT name,type,connected,path,permission,risk FROM shared_resource ORDER BY risk DESC, id", {});

    if (rows.isEmpty()) { loadDemoData(); return; }

    QVariantList filtered;
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        if (!kw.isEmpty()) {
            bool match = m["name"].toString().contains(kw, Qt::CaseInsensitive)
                      || m["path"].toString().contains(kw, Qt::CaseInsensitive);
            if (!match) continue;
        }
        if (!riskFilter.isEmpty() && m["risk"].toString() != riskFilter) continue;
        filtered << v;
    }
    fillTable(filtered);
}

void SharedResourcePage::loadDemoData()
{
    // 列：共享名称 / 种类 / 当前连接用户 / 映像路径 / 权限 / 风险
    struct SRow { QString name, type, users, path, perm, risk; };
    QList<SRow> demo = {
        {"ADMIN$",    "磁盘",   "0", "C:\\Windows",                   "完全控制", "正常"},
        {"C$",        "磁盘",   "0", "C:\\",                          "完全控制", "正常"},
        {"IPC$",      "IPC",    "1", "",                              "读取",     "正常"},
        {"SharedDocs","磁盘",   "2", "C:\\Users\\Public\\Documents",  "读写",     "中危"},
        {"malshare",  "磁盘",   "1", "C:\\Windows\\Temp\\malshare",   "完全控制", "高危"},
    };
    m_tbl->setRowCount(0);
    for (const auto &d : demo) {
        int r = m_tbl->rowCount(); m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(d.name));
        m_tbl->setItem(r, 1, new QTableWidgetItem(d.type));
        auto *ui_item = new QTableWidgetItem(d.users);
        ui_item->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 2, ui_item);
        m_tbl->setItem(r, 3, new QTableWidgetItem(d.path));
        m_tbl->setItem(r, 4, new QTableWidgetItem(d.perm));
        auto *ri = new QTableWidgetItem(d.risk);
        ri->setTextAlignment(Qt::AlignCenter);
        if      (d.risk == "高危") ri->setForeground(QColor("#e53e3e"));
        else if (d.risk == "中危") ri->setForeground(QColor("#dd6b20"));
        else                       ri->setForeground(QColor("#38a169"));
        m_tbl->setItem(r, 5, ri);
        if (d.risk == "高危")
            for (int c = 0; c < 6; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff5f5"));
    }
    m_lblStatus->setText(QString("共 %1 个共享资源").arg(demo.size()));
}

void SharedResourcePage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = m_tbl->rowCount(); m_tbl->insertRow(r);
        m_tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        m_tbl->setItem(r, 1, new QTableWidgetItem(m["type"].toString()));
        auto *ui_item = new QTableWidgetItem(m["connected"].toString());
        ui_item->setTextAlignment(Qt::AlignCenter);
        m_tbl->setItem(r, 2, ui_item);
        m_tbl->setItem(r, 3, new QTableWidgetItem(m["path"].toString()));
        m_tbl->setItem(r, 4, new QTableWidgetItem(m["permission"].toString()));
        QString risk = m["risk"].toString();
        auto *ri = new QTableWidgetItem(risk);
        ri->setTextAlignment(Qt::AlignCenter);
        if      (risk == "高危") ri->setForeground(QColor("#e53e3e"));
        else if (risk == "中危") ri->setForeground(QColor("#dd6b20"));
        else                     ri->setForeground(QColor("#38a169"));
        m_tbl->setItem(r, 5, ri);
        if (risk == "高危")
            for (int c = 0; c < 6; c++)
                if (m_tbl->item(r, c)) m_tbl->item(r, c)->setBackground(QColor("#fff5f5"));
    }
    m_lblStatus->setText(QString("共 %1 个共享资源").arg(rows.size()));
}
