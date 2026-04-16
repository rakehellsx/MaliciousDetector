#include "pages/MemoryImagePage.h"
#include "ui_MemoryImagePage.h"

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
    ui = new Ui::MemoryImagePage();
    ui->setupUi(this);
    postSetupUi();
    m_tblStatus = ui->m_tblStatus;
    m_tblKernel = ui->m_tblKernel;
    m_edtKernelKw = ui->m_edtKernelKw;
    m_cmbKernelTrusted = ui->m_cmbKernelTrusted;
    m_tblProc = ui->m_tblProc;
    m_edtProcKw = ui->m_edtProcKw;
    m_cmbProcSuspect = ui->m_cmbProcSuspect;
    m_lblKernelSummary = ui->m_lblKernelSummary;
    m_lblProcSummary = ui->m_lblProcSummary;
    m_btnSave = ui->m_btnSave;
    refreshData();
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
        if (kernelList.isEmpty() && procList.isEmpty()) {
            loadDemoData();
        } else {
            populateMemoryStatusFromDB(statusMap);
            populateKernelModulesFromDB(kernelList);
            populateProcessMemoryFromDB(procList);
        }
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

void MemoryImagePage::onQueryKernel()
{
    QString kw      = m_edtKernelKw->text().trimmed();
    int     trusted = m_cmbKernelTrusted->currentIndex(); // 0=全部,1=已签名,2=未签名

    QString sql = "SELECT name,base_address,image_size,flags,idx,path,is_trusted FROM kernel_module WHERE 1=1";
    QVariantList binds;
    if (!kw.isEmpty()) {
        sql += " AND (name LIKE ? OR path LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like;
    }
    if (trusted == 1) { sql += " AND is_trusted=1"; }
    if (trusted == 2) { sql += " AND is_trusted=0"; }
    sql += " ORDER BY is_trusted ASC, id";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    populateKernelModulesFromDB(rows);
}

void MemoryImagePage::onQueryProc()
{
    QString kw      = m_edtProcKw->text().trimmed();
    int     suspect = m_cmbProcSuspect->currentIndex(); // 0=全部,1=可疑注入,2=正常

    QString sql = "SELECT name,pid,private_mb,working_set_mb,virtual_mb,suspicious_inject FROM process_memory WHERE 1=1";
    QVariantList binds;
    if (!kw.isEmpty()) {
        sql += " AND (name LIKE ? OR CAST(pid AS TEXT) LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like;
    }
    if (suspect == 1) { sql += " AND suspicious_inject > 0"; }
    if (suspect == 2) { sql += " AND suspicious_inject = 0"; }
    sql += " ORDER BY suspicious_inject DESC, private_mb DESC";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    populateProcessMemoryFromDB(rows);
}

void MemoryImagePage::loadDemoData()
{
    // 内存状态演示数据
    m_tblStatus->setRowCount(0);
    auto addRow = [this](const QString &key, const QString &val) {
        int r = m_tblStatus->rowCount(); m_tblStatus->insertRow(r);
        QTableWidgetItem *k = new QTableWidgetItem(key);
        k->setBackground(QColor("#f5f7fa")); k->setForeground(QColor("#555"));
        QFont f = k->font(); f.setBold(true); k->setFont(f);
        m_tblStatus->setItem(r, 0, k);
        m_tblStatus->setItem(r, 1, new QTableWidgetItem(val));
    };
    addRow("物理内存总量", "8192 MB");
    addRow("已用内存",     "5120 MB（62.5%）");
    addRow("可用内存",     "3072 MB");
    addRow("虚拟内存",     "16384 MB");
    addRow("页面文件",     "C:\\pagefile.sys");

    // 内核模块演示数据（列：模块名/基址/大小/标志/索引/路径/授信状态）
    struct KRow { QString name, base, size, flags, idx, path; bool trusted; };
    QList<KRow> kDemo = {
        {"ntoskrnl.exe", "0xFFFFF80012000000", "8.5 MB", "0x00000004", "1",
         "C:\\Windows\\System32\\ntoskrnl.exe", true},
        {"hal.dll",      "0xFFFFF80012900000", "0.8 MB", "0x00000004", "2",
         "C:\\Windows\\System32\\hal.dll", true},
        {"kbdclass.sys", "0xFFFFF80013000000", "0.1 MB", "0x00000004", "3",
         "C:\\Windows\\System32\\drivers\\kbdclass.sys", true},
        {"rootkit.sys",  "0xFFFFF80014000000", "0.2 MB", "0x00000006", "4",
         "C:\\Windows\\Temp\\rootkit.sys", false},
        {"tcpip.sys",    "0xFFFFF80015000000", "1.2 MB", "0x00000004", "5",
         "C:\\Windows\\System32\\drivers\\tcpip.sys", true},
    };
    m_tblKernel->setRowCount(0);
    int untrusted = 0;
    for (const auto &k : kDemo) {
        int r = m_tblKernel->rowCount(); m_tblKernel->insertRow(r);
        m_tblKernel->setItem(r, 0, new QTableWidgetItem(k.name));
        auto *bi = new QTableWidgetItem(k.base); bi->setFont(QFont("Consolas", 10));
        m_tblKernel->setItem(r, 1, bi);
        m_tblKernel->setItem(r, 2, new QTableWidgetItem(k.size));
        m_tblKernel->setItem(r, 3, new QTableWidgetItem(k.flags));
        m_tblKernel->setItem(r, 4, new QTableWidgetItem(k.idx));
        auto *pi = new QTableWidgetItem(k.path); pi->setFont(QFont("Consolas", 10));
        m_tblKernel->setItem(r, 5, pi);
        auto *ti = new QTableWidgetItem(k.trusted ? "已签名" : "未签名");
        ti->setForeground(k.trusted ? QColor("#38a169") : QColor("#e53e3e"));
        QFont tf = ti->font(); tf.setBold(true); ti->setFont(tf);
        ti->setTextAlignment(Qt::AlignCenter);
        m_tblKernel->setItem(r, 6, ti);
        if (!k.trusted) {
            untrusted++;
            for (int c = 0; c < 7; c++)
                if (m_tblKernel->item(r, c)) m_tblKernel->item(r, c)->setBackground(QColor("#fff5f5"));
        }
    }
    m_lblKernelSummary->setText(QString("共 %1 条 ｜ 未签名 %2 条").arg(kDemo.size()).arg(untrusted));

    // 进程内存演示数据（列：进程名/PID/私有内存/工作集/虚拟内存/可疑注入）
    struct PRow { QString name, pid, priv, ws, virt, inject; bool high; };
    QList<PRow> pDemo = {
        {"explorer.exe",   "1234", "45 MB",  "120 MB", "280 MB",  "无",       false},
        {"svchost.exe",    "2048", "12 MB",  "35 MB",  "180 MB",  "无",       false},
        {"svchost32.exe",  "3721", "8 MB",   "25 MB",  "150 MB",  "检测到注入", true},
        {"chrome.exe",     "4096", "350 MB", "480 MB", "1200 MB", "无",       false},
        {"notepad.exe",    "5012", "5 MB",   "15 MB",  "80 MB",   "无",       false},
    };
    m_tblProc->setRowCount(0);
    int suspicious = 0;
    for (const auto &p : pDemo) {
        int r = m_tblProc->rowCount(); m_tblProc->insertRow(r);
        m_tblProc->setItem(r, 0, new QTableWidgetItem(p.name));
        m_tblProc->setItem(r, 1, new QTableWidgetItem(p.pid));
        m_tblProc->setItem(r, 2, new QTableWidgetItem(p.priv));
        m_tblProc->setItem(r, 3, new QTableWidgetItem(p.ws));
        m_tblProc->setItem(r, 4, new QTableWidgetItem(p.virt));
        auto *ii = new QTableWidgetItem(p.inject);
        ii->setTextAlignment(Qt::AlignCenter);
        if (p.high) { ii->setForeground(QColor("#e53e3e")); QFont f=ii->font(); f.setBold(true); ii->setFont(f); suspicious++; }
        else          ii->setForeground(QColor("#38a169"));
        m_tblProc->setItem(r, 5, ii);
        if (p.high)
            for (int c = 0; c < 6; c++)
                if (m_tblProc->item(r, c)) m_tblProc->item(r, c)->setBackground(QColor("#fff5f5"));
    }
    m_lblProcSummary->setText(QString("共 %1 条 ｜ 可疑注入 %2 条").arg(pDemo.size()).arg(suspicious));
}
