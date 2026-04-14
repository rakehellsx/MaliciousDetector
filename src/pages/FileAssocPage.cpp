#include "pages/FileAssocPage.h"
#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QDateTime>
#include <QFont>

FileAssocPage::FileAssocPage(QWidget *parent)
    : BasePage("文件关联检测", parent)
{
    setupUi();
    refreshData();
}

void FileAssocPage::setupUi()
{
    // ── 工具栏 ──────────────────────────────────────────────────────────────
    QHBoxLayout *toolRow = new QHBoxLayout;
    toolRow->setSpacing(6);

    m_btnScan = new QPushButton("扫描文件关联");
    m_btnScan->setFixedWidth(120);
    m_btnScan->setStyleSheet("QPushButton{background:#1a3a6a;color:#fff;border:none;border-radius:3px;"
                             "padding:5px 12px;font-size:12px;}"
                             "QPushButton:hover{background:#245090;}");
    connect(m_btnScan, &QPushButton::clicked, this, &FileAssocPage::refreshData);

    m_edtKeyword = new QLineEdit;
    m_edtKeyword->setPlaceholderText("扩展名 / 关联程序 / 路径");
    m_edtKeyword->setClearButtonEnabled(true);
    m_edtKeyword->setFixedWidth(200);
    connect(m_edtKeyword, &QLineEdit::returnPressed, this, &FileAssocPage::onQuery);

    m_cmbRisk = new QComboBox;
    m_cmbRisk->addItems({"全部风险", "高危(high)", "注意(medium)", "正常(low)"});
    connect(m_cmbRisk, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &FileAssocPage::onQuery);

    QPushButton *btnQuery   = new QPushButton("查询");
    btnQuery->setObjectName("btnPrimary");
    btnQuery->setFixedWidth(70);
    connect(btnQuery, &QPushButton::clicked, this, &FileAssocPage::onQuery);

    m_lblSummary = new QLabel;
    m_lblSummary->setStyleSheet("font-size:11px;color:#8c8c8c;padding:0 8px;");

    toolRow->addWidget(m_btnScan);
    toolRow->addSpacing(12);
    toolRow->addWidget(new QLabel("关键字："));
    toolRow->addWidget(m_edtKeyword);
    toolRow->addSpacing(8);
    toolRow->addWidget(new QLabel("风险："));
    toolRow->addWidget(m_cmbRisk);
    toolRow->addWidget(btnQuery);
    toolRow->addWidget(m_lblSummary);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    m_lblStatus = new QLabel;
    m_lblStatus->setObjectName("statusLabel");
    m_mainLayout->addWidget(m_lblStatus);

    // DB字段: ext, assoc_program, normal_value, current_value, risk_level
    m_tbl = new QTableWidget(0, 5);
    m_tbl->setHorizontalHeaderLabels({"扩展名", "关联程序", "正常值", "当前值", "风险"});
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tbl->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_tbl->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_tbl->verticalHeader()->setVisible(false);
    m_tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tbl->setAlternatingRowColors(true);
    m_tbl->setStyleSheet(
        "QTableWidget{border:1px solid #d0d7e3;font-size:12px;}"
        "QHeaderView::section{background:#e8ecf4;padding:5px 8px;font-weight:600;border:1px solid #d0d7e3;}"
        "QTableWidget::item{padding:5px 8px;}"
        "QTableWidget::item:alternate{background:#fafbfd;}");
    m_mainLayout->addWidget(m_tbl, 1);
}

void FileAssocPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbRisk->setCurrentIndex(0);
    onQuery();
}

void FileAssocPage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     riskIdx = m_cmbRisk->currentIndex();
    QStringList riskMap = {"", "high", "medium", "low"};
    QString riskFilter = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";

    QString sql = "SELECT ext,assoc_program,normal_value,current_value,risk_level "
                  "FROM file_assoc_scan WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (ext LIKE ? OR assoc_program LIKE ? OR current_value LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like;
    }
    if (!riskFilter.isEmpty()) {
        sql += " AND risk_level = ?";
        binds << riskFilter;
    }
    sql += " ORDER BY CASE risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void FileAssocPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    int highCount = 0, midCount = 0;

    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row, 0, new QTableWidgetItem(m["ext"].toString()));
        m_tbl->setItem(row, 1, new QTableWidgetItem(m["assoc_program"].toString()));
        QTableWidgetItem *ni = new QTableWidgetItem(m["normal_value"].toString());
        ni->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 2, ni);
        QTableWidgetItem *ci = new QTableWidgetItem(m["current_value"].toString());
        ci->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 3, ci);

        QString risk = m["risk_level"].toString();
        if (risk == "high") highCount++;
        else if (risk == "medium") midCount++;
        QString riskText = (risk=="high") ? "高危（已篡改）" : (risk=="medium") ? "注意" : "正常";
        QTableWidgetItem *ri = new QTableWidgetItem(riskText);
        QFont rf = ri->font(); rf.setBold(true); ri->setFont(rf);
        if (risk == "high") {
            ri->setForeground(QColor("#f5222d"));
            for (int c = 0; c < 5; c++)
                if (m_tbl->item(row, c)) m_tbl->item(row, c)->setBackground(QColor("#fff1f0"));
            if (m["normal_value"].toString() != m["current_value"].toString())
                ci->setForeground(QColor("#f5222d"));
        } else if (risk == "medium") {
            ri->setForeground(QColor("#fa8c16"));
            for (int c = 0; c < 5; c++)
                if (m_tbl->item(row, c)) m_tbl->item(row, c)->setBackground(QColor("#fffbe6"));
        } else {
            ri->setForeground(QColor("#52c41a"));
        }
        m_tbl->setItem(row, 4, ri);
    }

    QString summary = QString("共 %1 条").arg(rows.size());
    if (highCount > 0) summary += QString(" ｜ %1 条高危（已篡改）").arg(highCount);
    if (midCount > 0)  summary += QString(" ｜ %1 条注意").arg(midCount);
    m_lblSummary->setText(summary);
}
