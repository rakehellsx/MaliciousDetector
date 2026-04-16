#include "pages/AutorunPage.h"
#include "ui_AutorunPage.h"

#include "DatabaseManager.h"
#include <QTableWidgetItem>
#include <QPushButton>
#include <QColor>
#include <QHeaderView>

AutorunPage::AutorunPage(QWidget *parent)
    : BasePage("自启动项", parent)
{
    ui = new Ui::AutorunPage();
    ui->setupUi(this);
    postSetupUi();

    m_tabs       = findChild<QTabWidget*>("m_tabAutorun");
    m_tblReg     = ui->m_tblReg;
    m_tblFolder  = ui->m_tblFolder;
    m_tblMenu    = ui->m_tblMenu;
    m_tblDebug   = ui->m_tblDebug;
    m_edtKeyword = ui->m_edtKeyword;
    m_cmbRisk    = findChild<QComboBox*>("m_cmbRisk");
    m_lblStatus  = ui->m_lblStatus;

    for (auto *tbl : {m_tblReg, m_tblFolder, m_tblMenu, m_tblDebug}) {
        tbl->horizontalHeader()->setStretchLastSection(true);
        tbl->verticalHeader()->setVisible(false);
        tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
        tbl->setAlternatingRowColors(true);
    }

    connect(ui->btnQuery,   &QPushButton::clicked, this, &AutorunPage::onQuery);
    connect(ui->btnRefresh, &QPushButton::clicked, this, &AutorunPage::refreshData);
    connect(ui->btnExport,  &QPushButton::clicked, this, [this]{ m_lblStatus->setText("导出功能开发中..."); });

    refreshData();
}

void AutorunPage::refreshData()
{
    m_edtKeyword->clear();
    if (m_cmbRisk) m_cmbRisk->setCurrentIndex(0);
    onQuery();
}

void AutorunPage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     riskIdx = m_cmbRisk ? m_cmbRisk->currentIndex() : 0;
    QStringList riskMap = {"", "高危", "中危", "低危", "正常"};
    QString riskFilter = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";

    // 尝试从数据库读取
    auto rows = DatabaseManager::instance()->execSelect(
        "SELECT name,reg_path,value,cmd,publisher,risk,type FROM autorun_info ORDER BY risk DESC, id", {});

    if (rows.isEmpty()) {
        loadDemoData();
        return;
    }

    // 按 type 分组
    QVariantList regRows, folderRows, menuRows, debugRows;
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        QString type = m["type"].toString();
        if (!kw.isEmpty()) {
            bool match = m["name"].toString().contains(kw, Qt::CaseInsensitive)
                      || m["cmd"].toString().contains(kw, Qt::CaseInsensitive)
                      || m["publisher"].toString().contains(kw, Qt::CaseInsensitive);
            if (!match) continue;
        }
        if (!riskFilter.isEmpty() && m["risk"].toString() != riskFilter) continue;
        if      (type == "注册表")    regRows    << v;
        else if (type == "启动文件夹") folderRows << v;
        else if (type == "右键菜单")  menuRows   << v;
        else if (type == "调试器")    debugRows  << v;
    }
    fillTab(m_tblReg,    "注册表",    regRows);
    fillTab(m_tblFolder, "启动文件夹", folderRows);
    fillTab(m_tblMenu,   "右键菜单",  menuRows);
    fillTab(m_tblDebug,  "调试器",    debugRows);

    int total = m_tblReg->rowCount() + m_tblFolder->rowCount()
              + m_tblMenu->rowCount() + m_tblDebug->rowCount();
    m_lblStatus->setText(QString("共 %1 条自启动记录").arg(total));
}

// 演示数据（与原型一致）
void AutorunPage::loadDemoData()
{
    // ── 注册表启动项（6列）──
    m_tblReg->setRowCount(0);
    struct RegRow { QString name, regPath, value, cmd, pub, risk; };
    QList<RegRow> regDemo = {
        {"OneDrive",    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "OneDrive",
         "C:\\Users\\user01\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
         "Microsoft Corporation", "正常"},
        {"SecurityHealth", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SecurityHealth",
         "C:\\Windows\\System32\\SecurityHealthSystray.exe",
         "Microsoft Corporation", "正常"},
        {"svchost32",   "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "WindowsUpdate",
         "C:\\Windows\\Temp\\svchost32.exe",
         "未知", "高危"},
        {"ctfmon",      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "ctfmon",
         "C:\\Windows\\System32\\ctfmon.exe",
         "Microsoft Corporation", "正常"},
    };
    for (const auto &d : regDemo) {
        int r = m_tblReg->rowCount(); m_tblReg->insertRow(r);
        m_tblReg->setItem(r, 0, new QTableWidgetItem(d.name));
        m_tblReg->setItem(r, 1, new QTableWidgetItem(d.regPath));
        m_tblReg->setItem(r, 2, new QTableWidgetItem(d.value));
        m_tblReg->setItem(r, 3, new QTableWidgetItem(d.cmd));
        m_tblReg->setItem(r, 4, new QTableWidgetItem(d.pub));
        auto *ri = makeRiskItem(d.risk);
        m_tblReg->setItem(r, 5, ri);
        if (d.risk == "高危") highlightRow(m_tblReg, r, 6);
    }

    // ── 启动文件夹（4列）──
    m_tblFolder->setRowCount(0);
    struct FolderRow { QString name, cmd, pub, risk; };
    QList<FolderRow> folderDemo = {
        {"Adobe Acrobat Updater", "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AdobeARM.exe", "Adobe Inc.", "正常"},
        {"helper32",              "C:\\Windows\\Temp\\helper32.exe",                              "未知",        "中危"},
    };
    for (const auto &d : folderDemo) {
        int r = m_tblFolder->rowCount(); m_tblFolder->insertRow(r);
        m_tblFolder->setItem(r, 0, new QTableWidgetItem(d.name));
        m_tblFolder->setItem(r, 1, new QTableWidgetItem(d.cmd));
        m_tblFolder->setItem(r, 2, new QTableWidgetItem(d.pub));
        m_tblFolder->setItem(r, 3, makeRiskItem(d.risk));
        if (d.risk == "高危" || d.risk == "中危") highlightRow(m_tblFolder, r, 4);
    }

    // ── 右键菜单（4列）──
    m_tblMenu->setRowCount(0);
    struct MenuRow { QString name, regPath, cmd, risk; };
    QList<MenuRow> menuDemo = {
        {"7-Zip",         "HKCR\\*\\shell\\7-Zip",         "C:\\Program Files\\7-Zip\\7zFM.exe",    "正常"},
        {"Open with Code","HKCR\\*\\shell\\VSCode",         "C:\\Program Files\\VSCode\\Code.exe",   "正常"},
        {"RunMalware",    "HKCR\\*\\shell\\RunMalware",     "C:\\Windows\\Temp\\payload.exe",        "高危"},
    };
    for (const auto &d : menuDemo) {
        int r = m_tblMenu->rowCount(); m_tblMenu->insertRow(r);
        m_tblMenu->setItem(r, 0, new QTableWidgetItem(d.name));
        m_tblMenu->setItem(r, 1, new QTableWidgetItem(d.regPath));
        m_tblMenu->setItem(r, 2, new QTableWidgetItem(d.cmd));
        m_tblMenu->setItem(r, 3, makeRiskItem(d.risk));
        if (d.risk == "高危") highlightRow(m_tblMenu, r, 4);
    }

    // ── 系统调试器（4列）──
    m_tblDebug->setRowCount(0);
    struct DebugRow { QString name, regPath, cmd, risk; };
    QList<DebugRow> debugDemo = {
        {"notepad.exe", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe",
         "C:\\Windows\\Temp\\svchost32.exe", "高危"},
    };
    for (const auto &d : debugDemo) {
        int r = m_tblDebug->rowCount(); m_tblDebug->insertRow(r);
        m_tblDebug->setItem(r, 0, new QTableWidgetItem(d.name));
        m_tblDebug->setItem(r, 1, new QTableWidgetItem(d.regPath));
        m_tblDebug->setItem(r, 2, new QTableWidgetItem(d.cmd));
        m_tblDebug->setItem(r, 3, makeRiskItem(d.risk));
        if (d.risk == "高危") highlightRow(m_tblDebug, r, 4);
    }

    int total = m_tblReg->rowCount() + m_tblFolder->rowCount()
              + m_tblMenu->rowCount() + m_tblDebug->rowCount();
    m_lblStatus->setText(QString("共 %1 条自启动记录").arg(total));
}

void AutorunPage::fillTab(QTableWidget *tbl, const QString &type, const QVariantList &rows)
{
    tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int r = tbl->rowCount();
        tbl->insertRow(r);
        QString riskVal = m["risk"].toString();

        if (type == "注册表") {
            tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
            tbl->setItem(r, 1, new QTableWidgetItem(m["reg_path"].toString()));
            tbl->setItem(r, 2, new QTableWidgetItem(m["value"].toString()));
            tbl->setItem(r, 3, new QTableWidgetItem(m["cmd"].toString()));
            tbl->setItem(r, 4, new QTableWidgetItem(m["publisher"].toString()));
            tbl->setItem(r, 5, makeRiskItem(riskVal));
            if (riskVal == "高危") highlightRow(tbl, r, 6);
        } else if (type == "启动文件夹") {
            tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
            tbl->setItem(r, 1, new QTableWidgetItem(m["cmd"].toString()));
            tbl->setItem(r, 2, new QTableWidgetItem(m["publisher"].toString()));
            tbl->setItem(r, 3, makeRiskItem(riskVal));
            if (riskVal == "高危") highlightRow(tbl, r, 4);
        } else {
            tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
            tbl->setItem(r, 1, new QTableWidgetItem(m["reg_path"].toString()));
            tbl->setItem(r, 2, new QTableWidgetItem(m["cmd"].toString()));
            tbl->setItem(r, 3, makeRiskItem(riskVal));
            if (riskVal == "高危") highlightRow(tbl, r, 4);
        }
    }
}

QTableWidgetItem* AutorunPage::makeRiskItem(const QString &risk)
{
    auto *ri = new QTableWidgetItem(risk);
    ri->setTextAlignment(Qt::AlignCenter);
    if      (risk == "高危") ri->setForeground(QColor("#e53e3e"));
    else if (risk == "中危") ri->setForeground(QColor("#dd6b20"));
    else                     ri->setForeground(QColor("#38a169"));
    return ri;
}

void AutorunPage::highlightRow(QTableWidget *tbl, int r, int cols)
{
    for (int c = 0; c < cols; c++)
        if (tbl->item(r, c)) tbl->item(r, c)->setBackground(QColor("#fff5f5"));
}
