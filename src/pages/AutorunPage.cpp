#include "pages/AutorunPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>

AutorunPage::AutorunPage(QWidget *parent)
    : BasePage("\u81ea\u542f\u52a8\u9879", parent)
{
    setupUi();
    refreshData();
}

void AutorunPage::setupUi()
{
    QHBoxLayout *toolRow = new QHBoxLayout;
    QPushButton *btnRefresh = new QPushButton("\u5237\u65b0");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(80);
    connect(btnRefresh, &QPushButton::clicked, this, &AutorunPage::refreshData);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    m_tabs = new QTabWidget;
    auto makeTable = [this](QStringList headers) -> QTableWidget* {
        auto *t = new QTableWidget(0, headers.size());
        t->setHorizontalHeaderLabels(headers);
        styleTable(t);
        t->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        return t;
    };

    // DB字段: type, name, reg_path, value, cmd, publisher, risk
    // 注册表启动项: 名称 | 注册表路径 | 值/命令 | 发布商 | 风险
    m_tblReg    = makeTable({"\u542f\u52a8\u9879\u540d\u79f0", "\u6ce8\u518c\u8868\u8def\u5f84", "\u547d\u4ee4", "\u53d1\u5e03\u5546", "\u98ce\u9669"});
    // 启动文件夹: 名称 | 命令 | 发布商 | 风险
    m_tblFolder = makeTable({"\u6587\u4ef6\u540d", "\u547d\u4ee4", "\u53d1\u5e03\u5546", "\u98ce\u9669"});
    // 右键菜单: 名称 | 命令 | 发布商 | 风险
    m_tblMenu   = makeTable({"\u83dc\u5355\u9879", "\u547d\u4ee4", "\u53d1\u5e03\u5546", "\u98ce\u9669"});
    // 系统调试器: 名称 | 注册表路径 | 命令 | 发布商 | 风险
    m_tblDebug  = makeTable({"\u53ef\u6267\u884c\u6587\u4ef6", "\u6ce8\u518c\u8868\u8def\u5f84", "\u8c03\u8bd5\u5668\u8def\u5f84", "\u53d1\u5e03\u5546", "\u98ce\u9669"});

    m_tabs->addTab(m_tblReg,    "\u6ce8\u518c\u8868\u542f\u52a8\u9879");
    m_tabs->addTab(m_tblFolder, "\u542f\u52a8\u6587\u4ef6\u5939");
    m_tabs->addTab(m_tblMenu,   "\u53f3\u952e\u83dc\u5355");
    m_tabs->addTab(m_tblDebug,  "\u7cfb\u7edf\u8c03\u8bd5\u5668");
    m_mainLayout->addWidget(m_tabs, 1);
}

// 通用着色辅助
static void setRiskColor(QTableWidgetItem *item, const QString &risk)
{
    if (risk == "\u9ad8\u5371") item->setForeground(QColor("#ef5350"));
    else if (risk == "\u4e2d\u5371") item->setForeground(QColor("#ff9800"));
    else item->setForeground(QColor("#4caf50"));
    item->setTextAlignment(Qt::AlignCenter);
}

// 注册表启动项（5列）: 名称 | 注册表路径 | 命令 | 发布商 | 风险
static void fillRegTable(QTableWidget *tbl, const QVariantList &rows)
{
    tbl->setRowCount(0);
    for (const QVariant &_var : rows) {
        QVariantMap m = _var.toMap();
        if (m["type"].toString() != "reg" && m["type"].toString() != "registry") continue;
        int r = tbl->rowCount(); tbl->insertRow(r);
        tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        tbl->setItem(r, 1, new QTableWidgetItem(m["reg_path"].toString()));
        tbl->setItem(r, 2, new QTableWidgetItem(m["cmd"].toString()));
        tbl->setItem(r, 3, new QTableWidgetItem(m["publisher"].toString()));
        auto *ri = new QTableWidgetItem(m["risk"].toString());
        setRiskColor(ri, m["risk"].toString());
        tbl->setItem(r, 4, ri);
        if (m["risk"].toString() == "\u9ad8\u5371")
            for (int c = 0; c < 5; c++) if (tbl->item(r,c)) tbl->item(r,c)->setBackground(QColor("#fff1f0"));
    }
}

// 启动文件夹（4列）: 文件名 | 命令 | 发布商 | 风险
static void fillFolderTable(QTableWidget *tbl, const QVariantList &rows)
{
    tbl->setRowCount(0);
    for (const QVariant &_var : rows) {
        QVariantMap m = _var.toMap();
        if (m["type"].toString() != "folder") continue;
        int r = tbl->rowCount(); tbl->insertRow(r);
        tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        tbl->setItem(r, 1, new QTableWidgetItem(m["cmd"].toString()));
        tbl->setItem(r, 2, new QTableWidgetItem(m["publisher"].toString()));
        auto *ri = new QTableWidgetItem(m["risk"].toString());
        setRiskColor(ri, m["risk"].toString());
        tbl->setItem(r, 3, ri);
        if (m["risk"].toString() == "\u9ad8\u5371")
            for (int c = 0; c < 4; c++) if (tbl->item(r,c)) tbl->item(r,c)->setBackground(QColor("#fff1f0"));
    }
}

// 右键菜单（4列）: 菜单项 | 命令 | 发布商 | 风险
static void fillMenuTable(QTableWidget *tbl, const QVariantList &rows)
{
    tbl->setRowCount(0);
    for (const QVariant &_var : rows) {
        QVariantMap m = _var.toMap();
        if (m["type"].toString() != "menu" && m["type"].toString() != "rightclick") continue;
        int r = tbl->rowCount(); tbl->insertRow(r);
        tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        tbl->setItem(r, 1, new QTableWidgetItem(m["cmd"].toString()));
        tbl->setItem(r, 2, new QTableWidgetItem(m["publisher"].toString()));
        auto *ri = new QTableWidgetItem(m["risk"].toString());
        setRiskColor(ri, m["risk"].toString());
        tbl->setItem(r, 3, ri);
        if (m["risk"].toString() == "\u9ad8\u5371")
            for (int c = 0; c < 4; c++) if (tbl->item(r,c)) tbl->item(r,c)->setBackground(QColor("#fff1f0"));
    }
}

// 系统调试器（5列）: 可执行文件 | 注册表路径 | 调试器路径 | 发布商 | 风险
static void fillDebugTable(QTableWidget *tbl, const QVariantList &rows)
{
    tbl->setRowCount(0);
    for (const QVariant &_var : rows) {
        QVariantMap m = _var.toMap();
        if (m["type"].toString() != "debugger") continue;
        int r = tbl->rowCount(); tbl->insertRow(r);
        tbl->setItem(r, 0, new QTableWidgetItem(m["name"].toString()));
        tbl->setItem(r, 1, new QTableWidgetItem(m["reg_path"].toString()));
        tbl->setItem(r, 2, new QTableWidgetItem(m["cmd"].toString()));
        tbl->setItem(r, 3, new QTableWidgetItem(m["publisher"].toString()));
        auto *ri = new QTableWidgetItem(m["risk"].toString());
        setRiskColor(ri, m["risk"].toString());
        tbl->setItem(r, 4, ri);
        if (m["risk"].toString() == "\u9ad8\u5371")
            for (int c = 0; c < 5; c++) if (tbl->item(r,c)) tbl->item(r,c)->setBackground(QColor("#fff1f0"));
    }
}

void AutorunPage::refreshData()
{
    auto rows = DatabaseManager::instance()->queryAutorunInfo();
    fillRegTable(m_tblReg,       rows);
    fillFolderTable(m_tblFolder, rows);
    fillMenuTable(m_tblMenu,     rows);
    fillDebugTable(m_tblDebug,   rows);
    int total = m_tblReg->rowCount() + m_tblFolder->rowCount()
              + m_tblMenu->rowCount() + m_tblDebug->rowCount();
    m_lblStatus->setText(QString("\u5171 %1 \u4e2a\u81ea\u542f\u52a8\u9879").arg(total));
}
