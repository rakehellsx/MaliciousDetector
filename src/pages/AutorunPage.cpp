#include "pages/AutorunPage.h"
#include "ui_AutorunPage.h"

#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

AutorunPage::AutorunPage(QWidget *parent)
    : BasePage("自启动项", parent)
{
    ui = new Ui::AutorunPage();
    ui->setupUi(this);
    postSetupUi();
    m_tabs = findChild<QTabWidget*>("m_tabAutorun");
    m_tblReg = ui->m_tblReg;
    m_tblFolder = ui->m_tblFolder;
    m_tblMenu = ui->m_tblMenu;
    m_tblDebug = ui->m_tblDebug;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbRisk = findChild<QComboBox*>("m_cmbRisk");
    m_lblStatus = ui->m_lblStatus;
    refreshData();
}

void AutorunPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbRisk->setCurrentIndex(0);
    onQuery();
}

void AutorunPage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     riskIdx = m_cmbRisk->currentIndex();
    QStringList riskMap = {"", "高危", "中危", "低危"};
    QString riskFilter = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";

    fillTab(m_tblReg,    "注册表",    kw, riskFilter);
    fillTab(m_tblFolder, "启动文件夹", kw, riskFilter);
    fillTab(m_tblMenu,   "右键菜单",  kw, riskFilter);
    fillTab(m_tblDebug,  "调试器",    kw, riskFilter);

    int total = m_tblReg->rowCount() + m_tblFolder->rowCount()
              + m_tblMenu->rowCount() + m_tblDebug->rowCount();
    m_lblStatus->setText(QString("共 %1 条自启动记录").arg(total));
}

void AutorunPage::fillTab(QTableWidget *tbl, const QString &type,
                          const QString &kw, const QString &risk)
{
    tbl->setRowCount(0);

    QString sql = "SELECT name,reg_path,value,cmd,publisher,risk FROM autorun_info WHERE type=?";
    QVariantList binds;
    binds << type;

    if (!kw.isEmpty()) {
        sql += " AND (name LIKE ? OR reg_path LIKE ? OR cmd LIKE ? OR publisher LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like << like;
    }
    if (!risk.isEmpty()) {
        sql += " AND risk = ?";
        binds << risk;
    }
    sql += " ORDER BY risk DESC, id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);

    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = tbl->rowCount();
        tbl->insertRow(r);
        QString riskVal = m["risk"].toString();

        if (type == "注册表") {
            // 6列: name, reg_path, value, cmd, publisher, risk
            tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
            tbl->setItem(r, 1, new QTableWidgetItem(m["reg_path"].toString()));
            tbl->setItem(r, 2, new QTableWidgetItem(m["value"].toString()));
            tbl->setItem(r, 3, new QTableWidgetItem(m["cmd"].toString()));
            tbl->setItem(r, 4, new QTableWidgetItem(m["publisher"].toString()));
            auto *ri = new QTableWidgetItem(riskVal);
            if      (riskVal == "高危") ri->setForeground(QColor("#ef5350"));
            else if (riskVal == "中危") ri->setForeground(QColor("#ff9800"));
            else                        ri->setForeground(QColor("#4caf50"));
            ri->setTextAlignment(Qt::AlignCenter);
            tbl->setItem(r, 5, ri);
        } else if (type == "启动文件夹") {
            // 4列: name, cmd, publisher, risk
            tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
            tbl->setItem(r, 1, new QTableWidgetItem(m["cmd"].toString()));
            tbl->setItem(r, 2, new QTableWidgetItem(m["publisher"].toString()));
            auto *ri = new QTableWidgetItem(riskVal);
            if      (riskVal == "高危") ri->setForeground(QColor("#ef5350"));
            else if (riskVal == "中危") ri->setForeground(QColor("#ff9800"));
            else                        ri->setForeground(QColor("#4caf50"));
            ri->setTextAlignment(Qt::AlignCenter);
            tbl->setItem(r, 3, ri);
        } else {
            // 右键菜单/调试器 4列: name, reg_path, cmd, risk
            tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
            tbl->setItem(r, 1, new QTableWidgetItem(m["reg_path"].toString()));
            tbl->setItem(r, 2, new QTableWidgetItem(m["cmd"].toString()));
            auto *ri = new QTableWidgetItem(riskVal);
            if      (riskVal == "高危") ri->setForeground(QColor("#ef5350"));
            else if (riskVal == "中危") ri->setForeground(QColor("#ff9800"));
            else                        ri->setForeground(QColor("#4caf50"));
            ri->setTextAlignment(Qt::AlignCenter);
            tbl->setItem(r, 3, ri);
        }

        if (riskVal == "高危") {
            int cols = tbl->columnCount();
            for (int c = 0; c < cols; c++)
                if (tbl->item(r, c)) tbl->item(r, c)->setBackground(QColor("#fff1f0"));
        }
    }
}
