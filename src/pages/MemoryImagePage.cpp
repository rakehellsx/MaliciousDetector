#include "pages/MemoryImagePage.h"
#include "DatabaseManager.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QHeaderView>
#include <QDateTime>
#include <QMessageBox>

MemoryImagePage::MemoryImagePage(QWidget *parent)
    : BasePage("内存映像（系统）", parent)
{
    setupUi();
    refreshData();
}

void MemoryImagePage::setupUi()
{
    // 顶部工具栏：保存内存映像按钮
    m_btnSave = new QPushButton("保存内存映像");
    m_btnSave->setFixedWidth(120);
    m_btnSave->setStyleSheet(
        "QPushButton{background:#1a3a6a;color:#fff;border:none;border-radius:3px;padding:4px 10px;font-size:12px;}"
        "QPushButton:hover{background:#1e4a8a;}");
    connect(m_btnSave, &QPushButton::clicked, this, [this](){
        QMessageBox::information(this, "保存内存映像", "内存映像已保存至：C:\\MemDump\\memdump_" +
            QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".dmp");
    });
    // 工具栏行
    QHBoxLayout *toolRow = new QHBoxLayout;
    toolRow->setContentsMargins(0,0,0,4);
    toolRow->addWidget(m_btnSave);
    toolRow->addStretch();
    m_mainLayout->addLayout(toolRow);

    // 上半部分：左=内存运行状态，右=内核模块列表（水平分割）
    QSplitter *topSplitter = new QSplitter(Qt::Horizontal);

    // 内存运行状态 GroupBox
    QGroupBox *gbStatus = new QGroupBox("内存运行状态");
    gbStatus->setStyleSheet("QGroupBox{font-size:12px;font-weight:600;color:#1a3a6a;"
                            "border:1px solid #d0d7e3;border-radius:4px;margin-top:6px;padding-top:4px;}"
                            "QGroupBox::title{subcontrol-origin:margin;left:8px;}");
    QVBoxLayout *statusLayout = new QVBoxLayout(gbStatus);
    statusLayout->setContentsMargins(6,14,6,6);

    m_tblStatus = new QTableWidget(0, 2);
    m_tblStatus->setHorizontalHeaderLabels({"项目", "值"});
    m_tblStatus->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
    m_tblStatus->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_tblStatus->setColumnWidth(0, 130);
    m_tblStatus->verticalHeader()->setVisible(false);
    m_tblStatus->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tblStatus->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tblStatus->setAlternatingRowColors(true);
    m_tblStatus->setStyleSheet(
        "QTableWidget{border:1px solid #d0d7e3;font-size:12px;}"
        "QHeaderView::section{background:#e8ecf4;padding:5px 8px;font-weight:600;border:1px solid #d0d7e3;}"
        "QTableWidget::item{padding:5px 8px;}"
        "QTableWidget::item:alternate{background:#fafbfd;}");
    statusLayout->addWidget(m_tblStatus);
    topSplitter->addWidget(gbStatus);

    // 内核模块列表 GroupBox
    QGroupBox *gbKernel = new QGroupBox("内核模块列表");
    gbKernel->setStyleSheet(gbStatus->styleSheet());
    QVBoxLayout *kernelLayout = new QVBoxLayout(gbKernel);
    kernelLayout->setContentsMargins(6,14,6,6);

    m_tblKernel = new QTableWidget(0, 7);
    m_tblKernel->setHorizontalHeaderLabels({"模块名", "基址", "映像大小", "标志", "序号", "路径", "授信"});
    m_tblKernel->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tblKernel->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    m_tblKernel->verticalHeader()->setVisible(false);
    m_tblKernel->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tblKernel->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tblKernel->setAlternatingRowColors(true);
    m_tblKernel->setStyleSheet(m_tblStatus->styleSheet());
    kernelLayout->addWidget(m_tblKernel);

    m_lblKernelSummary = new QLabel();
    m_lblKernelSummary->setStyleSheet("font-size:11px;color:#8c8c8c;padding:3px 2px;");
    kernelLayout->addWidget(m_lblKernelSummary);
    topSplitter->addWidget(gbKernel);
    topSplitter->setStretchFactor(0, 1);
    topSplitter->setStretchFactor(1, 2);

    // 下半部分：进程内存映射
    QGroupBox *gbProc = new QGroupBox("进程内存映射（Top 5 占用）");
    gbProc->setStyleSheet(gbStatus->styleSheet());
    QVBoxLayout *procLayout = new QVBoxLayout(gbProc);
    procLayout->setContentsMargins(6,14,6,6);

    m_tblProc = new QTableWidget(0, 6);
    m_tblProc->setHorizontalHeaderLabels({"进程名", "PID", "私有内存", "工作集", "虚拟内存", "可疑注入"});
    m_tblProc->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tblProc->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_tblProc->verticalHeader()->setVisible(false);
    m_tblProc->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tblProc->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tblProc->setAlternatingRowColors(true);
    m_tblProc->setStyleSheet(m_tblStatus->styleSheet());
    procLayout->addWidget(m_tblProc);

    m_lblProcSummary = new QLabel();
    m_lblProcSummary->setStyleSheet("font-size:11px;color:#8c8c8c;padding:3px 2px;");
    procLayout->addWidget(m_lblProcSummary);

    // 垂直分割：上(topSplitter) + 下(gbProc)
    QSplitter *mainSplitter = new QSplitter(Qt::Vertical);
    mainSplitter->addWidget(topSplitter);
    mainSplitter->addWidget(gbProc);
    mainSplitter->setStretchFactor(0, 3);
    mainSplitter->setStretchFactor(1, 2);

    m_mainLayout->addWidget(mainSplitter);
}

void MemoryImagePage::refreshData()
{
    // 优先从 basic.dll 获取（返回 QJsonObject）
    if (m_loader && m_loader->isLoaded()) {
        QJsonObject data = m_loader->getMemoryImageInfo();
        populateMemoryStatus(data);
        populateKernelModules(data);
        populateProcessMemory(data);
    } else {
        // 从 DatabaseManager 专用接口读取（返回 QVariantMap）
        QVariantMap statusMap = DatabaseManager::instance()->queryMemoryStatus();
        QVariantList kernelList = DatabaseManager::instance()->queryKernelModules();
        QVariantList procList   = DatabaseManager::instance()->queryProcessMemory();
        populateMemoryStatusFromDB(statusMap);
        populateKernelModulesFromDB(kernelList);
        populateProcessMemoryFromDB(procList);
    }

    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void MemoryImagePage::populateMemoryStatus(const QJsonObject &data)
{
    m_tblStatus->setRowCount(0);
    auto addRow = [this](const QString &key, const QString &val) {
        int r = m_tblStatus->rowCount();
        m_tblStatus->insertRow(r);
        QTableWidgetItem *k = new QTableWidgetItem(key);
        k->setBackground(QColor("#f5f7fa"));
        k->setForeground(QColor("#555"));
        QFont f = k->font(); f.setBold(true); k->setFont(f);
        m_tblStatus->setItem(r, 0, k);
        m_tblStatus->setItem(r, 1, new QTableWidgetItem(val));
    };

    int total = data.value("total_physical_mb").toInt(0);
    int used  = data.value("used_physical_mb").toInt(0);
    double pct = total > 0 ? (double)used / total * 100.0 : 0.0;
    int avail = data.value("available_physical_mb").toInt(0);
    int virt  = data.value("virtual_memory_mb").toInt(0);
    QString pf = data.value("page_file").toString("");

    addRow("物理内存总量",  QString("%1 MB").arg(total));
    addRow("已用内存",      QString("%1 MB（%2%）").arg(used).arg(pct, 0, 'f', 1));
    addRow("可用内存",      QString("%1 MB").arg(avail));
    addRow("虚拟内存",      QString("%1 MB").arg(virt));
    addRow("页面文件",      pf);
}

void MemoryImagePage::populateMemoryStatusFromDB(const QVariantMap &row)
{
    m_tblStatus->setRowCount(0);
    auto addRow = [this](const QString &key, const QString &val) {
        int r = m_tblStatus->rowCount();
        m_tblStatus->insertRow(r);
        QTableWidgetItem *k = new QTableWidgetItem(key);
        k->setBackground(QColor("#f5f7fa"));
        k->setForeground(QColor("#555"));
        QFont f = k->font(); f.setBold(true); k->setFont(f);
        m_tblStatus->setItem(r, 0, k);
        m_tblStatus->setItem(r, 1, new QTableWidgetItem(val));
    };

    int total = row.value("total_mb").toInt();
    int used  = row.value("used_mb").toInt();
    int avail = row.value("avail_mb").toInt();
    int virt  = row.value("virtual_mb").toInt();
    QString pf = row.value("page_file").toString();
    double pct = total > 0 ? (double)used / total * 100.0 : 0.0;

    addRow("物理内存总量",  QString("%1 MB").arg(total));
    addRow("已用内存",      QString("%1 MB（%2%）").arg(used).arg(pct, 0, 'f', 1));
    addRow("可用内存",      QString("%1 MB").arg(avail));
    addRow("虚拟内存",      QString("%1 MB").arg(virt));
    addRow("页面文件",      pf);
}

void MemoryImagePage::populateKernelModules(const QJsonObject &data)
{
    m_tblKernel->setRowCount(0);
    QJsonArray modules = data.value("kernel_modules").toArray();
    int untrusted = 0;

    for (const QJsonValue &v : modules) {
        QJsonObject m = v.toObject();
        int row = m_tblKernel->rowCount();
        m_tblKernel->insertRow(row);

        bool trusted = m.value("is_trusted").toBool(true);
        if (!trusted) untrusted++;

        m_tblKernel->setItem(row, 0, new QTableWidgetItem(m.value("name").toString()));
        QTableWidgetItem *baseItem = new QTableWidgetItem(m.value("base_address").toString());
        baseItem->setFont(QFont("Consolas", 11));
        m_tblKernel->setItem(row, 1, baseItem);
        m_tblKernel->setItem(row, 2, new QTableWidgetItem(m.value("image_size").toString()));
        m_tblKernel->setItem(row, 3, new QTableWidgetItem(m.value("flags").toString()));
        m_tblKernel->setItem(row, 4, new QTableWidgetItem(QString::number(m.value("index").toInt())));
        QTableWidgetItem *pathItem = new QTableWidgetItem(m.value("path").toString());
        pathItem->setFont(QFont("Consolas", 11));
        m_tblKernel->setItem(row, 5, pathItem);

        QTableWidgetItem *ti = new QTableWidgetItem(trusted ? "已签名" : "未签名");
        ti->setForeground(trusted ? QColor("#52c41a") : QColor("#f5222d"));
        QFont tf = ti->font(); tf.setBold(true); ti->setFont(tf);
        m_tblKernel->setItem(row, 6, ti);

        if (!trusted) {
            for (int c = 0; c < 7; c++) {
                if (m_tblKernel->item(row, c))
                    m_tblKernel->item(row, c)->setBackground(QColor("#fff1f0"));
            }
        }
    }

    QString summary = QString("共 %1 条").arg(modules.size());
    if (untrusted > 0)
        summary += QString(" ｜ <span style='color:#f5222d'>%1 条未签名内核模块</span>").arg(untrusted);
    m_lblKernelSummary->setText(summary);
}

void MemoryImagePage::populateKernelModulesFromDB(const QVariantList &rows)
{
    m_tblKernel->setRowCount(0);
    int untrusted = 0;

    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = m_tblKernel->rowCount();
        m_tblKernel->insertRow(row);

        bool trusted = m.value("is_trusted").toBool();
        if (!trusted) untrusted++;

        m_tblKernel->setItem(row, 0, new QTableWidgetItem(m.value("name").toString()));
        QTableWidgetItem *baseItem = new QTableWidgetItem(m.value("base_address").toString());
        baseItem->setFont(QFont("Consolas", 11));
        m_tblKernel->setItem(row, 1, baseItem);
        m_tblKernel->setItem(row, 2, new QTableWidgetItem(m.value("image_size").toString()));
        m_tblKernel->setItem(row, 3, new QTableWidgetItem(m.value("flags").toString()));
        m_tblKernel->setItem(row, 4, new QTableWidgetItem(m.value("idx").toString()));
        QTableWidgetItem *pathItem = new QTableWidgetItem(m.value("path").toString());
        pathItem->setFont(QFont("Consolas", 11));
        m_tblKernel->setItem(row, 5, pathItem);

        QTableWidgetItem *ti = new QTableWidgetItem(trusted ? "已签名" : "未签名");
        ti->setForeground(trusted ? QColor("#52c41a") : QColor("#f5222d"));
        QFont tf = ti->font(); tf.setBold(true); ti->setFont(tf);
        m_tblKernel->setItem(row, 6, ti);

        if (!trusted) {
            for (int c = 0; c < 7; c++) {
                if (m_tblKernel->item(row, c))
                    m_tblKernel->item(row, c)->setBackground(QColor("#fff1f0"));
            }
        }
    }

    QString summary = QString("共 %1 条").arg(rows.size());
    if (untrusted > 0)
        summary += QString(" ｜ <span style='color:#f5222d'>%1 条未签名内核模块</span>").arg(untrusted);
    m_lblKernelSummary->setText(summary);
}

void MemoryImagePage::populateProcessMemory(const QJsonObject &data)
{
    m_tblProc->setRowCount(0);
    QJsonArray procs = data.value("process_memory").toArray();
    int suspicious = 0;

    for (const QJsonValue &v : procs) {
        QJsonObject p = v.toObject();
        int row = m_tblProc->rowCount();
        m_tblProc->insertRow(row);

        QJsonValue injectVal = p.value("suspicious_inject");
        QString injectText;
        QColor rowBg;
        bool isHighRisk = false;
        bool isMedRisk = false;

        if (injectVal.isNull() || injectVal.isUndefined()) {
            injectText = "可疑";
            rowBg = QColor("#fffbe6");
            isMedRisk = true;
        } else if (injectVal.toBool()) {
            injectText = "检测到注入";
            rowBg = QColor("#fff1f0");
            isHighRisk = true;
        } else {
            injectText = "无";
        }

        if (isHighRisk || isMedRisk) suspicious++;

        m_tblProc->setItem(row, 0, new QTableWidgetItem(p.value("name").toString()));
        m_tblProc->setItem(row, 1, new QTableWidgetItem(QString::number(p.value("pid").toInt())));
        m_tblProc->setItem(row, 2, new QTableWidgetItem(QString("%1 MB").arg(p.value("private_mb").toInt())));
        m_tblProc->setItem(row, 3, new QTableWidgetItem(QString("%1 MB").arg(p.value("working_set_mb").toInt())));
        m_tblProc->setItem(row, 4, new QTableWidgetItem(QString("%1 MB").arg(p.value("virtual_mb").toInt())));

        QTableWidgetItem *injectItem = new QTableWidgetItem(injectText);
        if (isHighRisk) {
            injectItem->setForeground(QColor("#f5222d"));
            QFont f = injectItem->font(); f.setBold(true); injectItem->setFont(f);
        } else if (isMedRisk) {
            injectItem->setForeground(QColor("#fa8c16"));
            QFont f = injectItem->font(); f.setBold(true); injectItem->setFont(f);
        } else {
            injectItem->setForeground(QColor("#52c41a"));
        }
        m_tblProc->setItem(row, 5, injectItem);

        if (isHighRisk || isMedRisk) {
            for (int c = 0; c < 6; c++) {
                if (m_tblProc->item(row, c))
                    m_tblProc->item(row, c)->setBackground(rowBg);
            }
        }
    }

    QString summary = QString("共 %1 条").arg(procs.size());
    if (suspicious > 0)
        summary += QString(" ｜ <span style='color:#f5222d'>%1 条可疑进程</span>").arg(suspicious);
    m_lblProcSummary->setText(summary);
}

void MemoryImagePage::populateProcessMemoryFromDB(const QVariantList &rows)
{
    m_tblProc->setRowCount(0);
    int suspicious = 0;

    for (const QVariant &v : rows) {
        QVariantMap p = v.toMap();
        int row = m_tblProc->rowCount();
        m_tblProc->insertRow(row);

        int injectVal = p.value("suspicious_inject").toInt(); // 0=无, 1=可疑, 2=注入
        QString injectText;
        QColor rowBg;
        bool isHighRisk = false;
        bool isMedRisk = false;

        if (injectVal == 2) {
            injectText = "检测到注入";
            rowBg = QColor("#fff1f0");
            isHighRisk = true;
        } else if (injectVal == 1) {
            injectText = "可疑";
            rowBg = QColor("#fffbe6");
            isMedRisk = true;
        } else {
            injectText = "无";
        }

        if (isHighRisk || isMedRisk) suspicious++;

        m_tblProc->setItem(row, 0, new QTableWidgetItem(p.value("name").toString()));
        m_tblProc->setItem(row, 1, new QTableWidgetItem(p.value("pid").toString()));
        m_tblProc->setItem(row, 2, new QTableWidgetItem(QString("%1 MB").arg(p.value("private_mb").toInt())));
        m_tblProc->setItem(row, 3, new QTableWidgetItem(QString("%1 MB").arg(p.value("working_set_mb").toInt())));
        m_tblProc->setItem(row, 4, new QTableWidgetItem(QString("%1 MB").arg(p.value("virtual_mb").toInt())));

        QTableWidgetItem *injectItem = new QTableWidgetItem(injectText);
        if (isHighRisk) {
            injectItem->setForeground(QColor("#f5222d"));
            QFont f = injectItem->font(); f.setBold(true); injectItem->setFont(f);
        } else if (isMedRisk) {
            injectItem->setForeground(QColor("#fa8c16"));
            QFont f = injectItem->font(); f.setBold(true); injectItem->setFont(f);
        } else {
            injectItem->setForeground(QColor("#52c41a"));
        }
        m_tblProc->setItem(row, 5, injectItem);

        if (isHighRisk || isMedRisk) {
            for (int c = 0; c < 6; c++) {
                if (m_tblProc->item(row, c))
                    m_tblProc->item(row, c)->setBackground(rowBg);
            }
        }
    }

    QString summary = QString("共 %1 条").arg(rows.size());
    if (suspicious > 0)
        summary += QString(" ｜ <span style='color:#f5222d'>%1 条可疑进程</span>").arg(suspicious);
    m_lblProcSummary->setText(summary);
}
