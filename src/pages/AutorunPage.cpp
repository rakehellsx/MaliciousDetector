#include "pages/AutorunPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>

AutorunPage::AutorunPage(QWidget *parent)
    : BasePage("自启动项", parent)
{
    setupUi();
    refreshData();
}

void AutorunPage::setupUi()
{
    // ── 查询栏 ──────────────────────────────────────────────────────────────
    QHBoxLayout *toolRow = new QHBoxLayout;
    toolRow->setSpacing(6);

    m_edtKeyword = new QLineEdit;
    m_edtKeyword->setPlaceholderText("名称 / 注册表路径 / 命令 / 发布商");
    m_edtKeyword->setClearButtonEnabled(true);
    m_edtKeyword->setFixedWidth(260);
    connect(m_edtKeyword, &QLineEdit::returnPressed, this, &AutorunPage::onQuery);

    m_cmbRisk = new QComboBox;
    m_cmbRisk->addItems({"全部风险", "高危", "中危", "低危"});
    connect(m_cmbRisk, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AutorunPage::onQuery);

    QPushButton *btnQuery   = new QPushButton("查询");
    btnQuery->setObjectName("btnPrimary");
    btnQuery->setFixedWidth(70);
    connect(btnQuery, &QPushButton::clicked, this, &AutorunPage::onQuery);

    QPushButton *btnRefresh = new QPushButton("刷新");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(70);
    connect(btnRefresh, &QPushButton::clicked, this, &AutorunPage::refreshData);

    toolRow->addWidget(new QLabel("关键字："));
    toolRow->addWidget(m_edtKeyword);
    toolRow->addSpacing(8);
    toolRow->addWidget(new QLabel("风险："));
    toolRow->addWidget(m_cmbRisk);
    toolRow->addWidget(btnQuery);
    toolRow->addWidget(btnRefresh);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    m_lblStatus = new QLabel;
    m_lblStatus->setObjectName("statusLabel");
    m_mainLayout->addWidget(m_lblStatus);

    // ── Tab 控件 ─────────────────────────────────────────────────────────────
    m_tabs = new QTabWidget;
    m_mainLayout->addWidget(m_tabs, 1);

    auto makeTable = [this](QStringList headers) -> QTableWidget* {
        auto *t = new QTableWidget(0, headers.size());
        t->setHorizontalHeaderLabels(headers);
        styleTable(t);
        t->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        return t;
    };

    // DB字段: type, name, reg_path, value, cmd, publisher, risk
    // 注册表启动项 (type=注册表): 名称 | 注册表路径 | 值名 | 命令 | 发布商 | 风险
    m_tblReg    = makeTable({"启动项名称", "注册表路径", "值名", "命令", "发布商", "风险"});
    // 启动文件夹 (type=启动文件夹): 文件名 | 命令 | 发布商 | 风险
    m_tblFolder = makeTable({"文件名", "命令", "发布商", "风险"});
    // 右键菜单 (type=右键菜单): 菜单项 | 注册表路径 | 命令 | 风险
    m_tblMenu   = makeTable({"菜单项", "注册表路径", "命令", "风险"});
    // 调试器劫持 (type=调试器): 目标程序 | 注册表路径 | 调试器命令 | 风险
    m_tblDebug  = makeTable({"目标程序", "注册表路径", "调试器命令", "风险"});

    m_tabs->addTab(m_tblReg,    "注册表启动项");
    m_tabs->addTab(m_tblFolder, "启动文件夹");
    m_tabs->addTab(m_tblMenu,   "右键菜单");
    m_tabs->addTab(m_tblDebug,  "调试器劫持");
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
