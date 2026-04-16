#include "pages/VulnDetectPage.h"
#include "ui_VulnDetectPage.h"
#include "DatabaseManager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QFrame>
#include <QDialogButtonBox>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QTextStream>
#include <QLabel>

// ─────────────────────────────────────────────────────────────────────────────
// 静态辅助
// ─────────────────────────────────────────────────────────────────────────────
static QTableWidgetItem* riskItem(const QString &risk) {
    QString text = (risk == "high") ? "高危" : (risk == "medium") ? "中危" : "低危";
    auto *item = new QTableWidgetItem(text);
    QFont f = item->font(); f.setBold(true); item->setFont(f);
    if      (risk == "high")   item->setForeground(QColor("#f5222d"));
    else if (risk == "medium") item->setForeground(QColor("#fa8c16"));
    else                       item->setForeground(QColor("#1890ff"));
    return item;
}

// ─────────────────────────────────────────────────────────────────────────────
// 构造
// ─────────────────────────────────────────────────────────────────────────────
VulnDetectPage::VulnDetectPage(QWidget *parent)
    : BasePage("漏洞监测", parent)
{
    ui = new Ui::VulnDetectPage();
    ui->setupUi(this);
    postSetupUi();

    // 绑定控件
    m_edtSearch  = ui->m_edtSearch;
    m_cmbRisk    = ui->m_cmbRisk;
    m_cmbProto   = ui->m_cmbProto;
    m_btnQuery   = ui->m_btnQuery;
    m_btnExport  = ui->m_btnExport;
    m_tblVuln    = ui->m_tblVuln;

    // 表格配置
    m_tblVuln->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tblVuln->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_tblVuln->verticalHeader()->setVisible(false);
    m_tblVuln->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tblVuln->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tblVuln->setAlternatingRowColors(true);

    // 按钮样式
    m_btnQuery->setStyleSheet(
        "QPushButton{background:#1a3a6a;color:#fff;border:none;border-radius:3px;padding:4px 12px;}"
        "QPushButton:hover{background:#2a5a9a;}");
    m_btnExport->setStyleSheet(
        "QPushButton{background:#595959;color:#fff;border:none;border-radius:3px;padding:4px 12px;}"
        "QPushButton:hover{background:#737373;}");

    // 信号
    connect(m_btnQuery,  &QPushButton::clicked, this, &VulnDetectPage::onQuery);
    connect(m_btnExport, &QPushButton::clicked, this, &VulnDetectPage::onExport);
    connect(m_edtSearch, &QLineEdit::returnPressed, this, &VulnDetectPage::onQuery);
    connect(m_tblVuln, &QTableWidget::cellDoubleClicked, [this](int row, int) {
        if (row >= 0 && row < m_dataCache.size())
            showDetailDialog(m_dataCache[row]);
    });

    refreshData();
}

VulnDetectPage::~VulnDetectPage() { delete ui; }

void VulnDetectPage::refreshData() { loadData(); }

void VulnDetectPage::loadData()
{
    m_tblVuln->setRowCount(0);
    m_dataCache.clear();

    QString kw   = m_edtSearch->text().trimmed();
    int riskIdx  = m_cmbRisk->currentIndex();
    int protoIdx = m_cmbProto->currentIndex();

    static const QStringList riskMap  = {"", "high", "medium", "low"};
    static const QStringList protoMap = {"", "TCP", "UDP", "HTTP", "HTTPS", "SMB", "RDP"};

    QString sql =
        "SELECT proc_path, pid, tool_name, description, "
        "  src_ip, src_port, dst_ip, dst_port, protocol, risk_level, "
        "  cve_id, cve_publish, cvss_score, vuln_component, vuln_desc, detect_time "
        "FROM vuln_detect WHERE 1=1";
    QVariantList binds;
    if (!kw.isEmpty()) {
        sql += " AND (proc_path LIKE ? OR tool_name LIKE ? OR cve_id LIKE ? "
               "  OR src_ip LIKE ? OR dst_ip LIKE ? OR description LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like << like << like << like;
    }
    if (riskIdx > 0 && riskIdx < riskMap.size())   { sql += " AND risk_level=?"; binds << riskMap[riskIdx]; }
    if (protoIdx > 0 && protoIdx < protoMap.size()) { sql += " AND protocol=?";   binds << protoMap[protoIdx]; }
    sql += " ORDER BY id DESC LIMIT 500";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);

    // 若数据库无数据，使用演示数据
    if (rows.isEmpty()) {
        rows = QList<QVariant>{
            QVariant(QVariantMap{
                {"proc_path","C:\\Windows\\System32\\lsass.exe"}, {"pid","612"},
                {"tool_name","EternalBlue"}, {"description","利用SMB协议漏洞进行横向移动"},
                {"src_ip","192.168.1.105"}, {"src_port","49152"},
                {"dst_ip","192.168.1.10"},  {"dst_port","445"},
                {"protocol","SMB"}, {"risk_level","high"},
                {"cve_id","CVE-2017-0144"}, {"cve_publish","2017-03-14"},
                {"cvss_score","9.3"}, {"vuln_component","Windows SMBv1"},
                {"vuln_desc","SMBv1服务器处理特定请求时存在远程代码执行漏洞，攻击者可利用该漏洞在目标系统上执行任意代码。"},
                {"detect_time","2025-04-16 09:12:34"}
            }),
            QVariant(QVariantMap{
                {"proc_path","C:\\Windows\\Temp\\mimikatz.exe"}, {"pid","3892"},
                {"tool_name","Mimikatz"}, {"description","转储系统凭证，利用SAM数据库漏洞"},
                {"src_ip","192.168.1.105"}, {"src_port","0"},
                {"dst_ip","127.0.0.1"},     {"dst_port","0"},
                {"protocol","TCP"}, {"risk_level","high"},
                {"cve_id","CVE-2021-36934"}, {"cve_publish","2021-07-20"},
                {"cvss_score","7.8"}, {"vuln_component","Windows SAM/LSA"},
                {"vuln_desc","Windows系统SAM数据库和LSA机密文件访问权限配置不当，允许非特权用户读取敏感凭证信息。"},
                {"detect_time","2025-04-16 09:15:22"}
            }),
            QVariant(QVariantMap{
                {"proc_path","C:\\Windows\\System32\\spoolsv.exe"}, {"pid","1456"},
                {"tool_name","PrintNightmare"}, {"description","利用打印后台服务漏洞提权"},
                {"src_ip","192.168.1.200"}, {"src_port","49200"},
                {"dst_ip","192.168.1.10"},  {"dst_port","445"},
                {"protocol","SMB"}, {"risk_level","high"},
                {"cve_id","CVE-2021-34527"}, {"cve_publish","2021-07-01"},
                {"cvss_score","8.8"}, {"vuln_component","Windows Print Spooler"},
                {"vuln_desc","Windows打印后台处理程序服务不正确地执行特权文件操作，远程攻击者可利用此漏洞以SYSTEM权限执行任意代码。"},
                {"detect_time","2025-04-16 09:18:05"}
            }),
            QVariant(QVariantMap{
                {"proc_path","C:\\Program Files\\Apache\\bin\\java.exe"}, {"pid","2048"},
                {"tool_name","Log4Shell"}, {"description","利用Log4j2 JNDI注入漏洞执行远程代码"},
                {"src_ip","185.220.101.45"}, {"src_port","443"},
                {"dst_ip","192.168.1.50"},   {"dst_port","8080"},
                {"protocol","HTTPS"}, {"risk_level","high"},
                {"cve_id","CVE-2021-44228"}, {"cve_publish","2021-12-10"},
                {"cvss_score","10.0"}, {"vuln_component","Apache Log4j2"},
                {"vuln_desc","Apache Log4j2存在JNDI注入漏洞，攻击者可通过构造恶意请求触发JNDI查找，实现远程代码执行，CVSS评分满分10.0。"},
                {"detect_time","2025-04-16 09:22:41"}
            }),
            QVariant(QVariantMap{
                {"proc_path","C:\\Windows\\System32\\termdd.sys"}, {"pid","4"},
                {"tool_name","BlueKeep"}, {"description","利用RDP协议漏洞进行蠕虫式传播"},
                {"src_ip","10.0.0.100"}, {"src_port","49300"},
                {"dst_ip","192.168.1.10"}, {"dst_port","3389"},
                {"protocol","RDP"}, {"risk_level","high"},
                {"cve_id","CVE-2019-0708"}, {"cve_publish","2019-05-14"},
                {"cvss_score","9.8"}, {"vuln_component","Windows Remote Desktop Services"},
                {"vuln_desc","Windows远程桌面服务存在远程代码执行漏洞，无需身份验证的攻击者可通过发送特制请求触发漏洞，可能导致蠕虫式传播。"},
                {"detect_time","2025-04-16 09:30:18"}
            })
        };
    }

    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        m_dataCache.append(m);
        int row = m_tblVuln->rowCount();
        m_tblVuln->insertRow(row);

        auto setItem = [&](int col, const QString &text) {
            auto *it = new QTableWidgetItem(text);
            if (col == 0) it->setFont(QFont("Consolas", 10));
            m_tblVuln->setItem(row, col, it);
        };
        setItem(0, m["proc_path"].toString());
        setItem(1, m["pid"].toString());
        setItem(2, m["tool_name"].toString());
        setItem(3, m["description"].toString());
        setItem(4, m["src_ip"].toString());
        setItem(5, m["src_port"].toString());
        setItem(6, m["dst_ip"].toString());
        setItem(7, m["dst_port"].toString());
        setItem(8, m["protocol"].toString());
        m_tblVuln->setItem(row, 9, riskItem(m["risk_level"].toString()));

        // 详情按钮
        auto *btnDetail = new QPushButton("详情");
        btnDetail->setStyleSheet(
            "QPushButton{background:#1890ff;color:#fff;border:none;"
            "border-radius:2px;padding:2px 10px;font-size:11px;}"
            "QPushButton:hover{background:#40a9ff;}");
        int captureRow = row;
        connect(btnDetail, &QPushButton::clicked, [this, captureRow]() {
            if (captureRow < m_dataCache.size())
                showDetailDialog(m_dataCache[captureRow]);
        });
        m_tblVuln->setCellWidget(row, 10, btnDetail);

        if (m["risk_level"].toString() == "high") {
            for (int c = 0; c < 10; c++)
                if (m_tblVuln->item(row, c))
                    m_tblVuln->item(row, c)->setBackground(QColor("#fff1f0"));
        }
    }

    if (m_lblStatus)
        m_lblStatus->setText(QString("共 %1 条漏洞记录  |  已刷新：%2")
            .arg(m_tblVuln->rowCount())
            .arg(QDateTime::currentDateTime().toString("HH:mm:ss")));
}

void VulnDetectPage::onQuery() { loadData(); }

void VulnDetectPage::showDetailDialog(const QVariantMap &rec)
{
    QDialog dlg(this);
    dlg.setWindowTitle("漏洞详情 — " + rec["cve_id"].toString());
    dlg.setMinimumWidth(600);
    dlg.setMinimumHeight(520);

    auto *mainLay = new QVBoxLayout(&dlg);
    mainLay->setContentsMargins(16, 16, 16, 16);
    mainLay->setSpacing(12);

    auto makeSection = [](const QString &title) -> QGroupBox* {
        auto *gb = new QGroupBox(title);
        gb->setStyleSheet(
            "QGroupBox{font-size:13px;font-weight:700;color:#1a3a6a;"
            "  border:1px solid #d0d7e3;border-radius:4px;margin-top:8px;padding-top:8px;}"
            "QGroupBox::title{subcontrol-origin:margin;left:10px;padding:0 4px;}");
        return gb;
    };

    auto addKV = [](QFormLayout *form, const QString &key, const QString &val,
                    bool mono = false, bool bold = false) {
        auto *lbl = new QLabel(val);
        lbl->setWordWrap(true);
        if (mono) lbl->setFont(QFont("Consolas", 10));
        if (bold) { QFont f = lbl->font(); f.setBold(true); lbl->setFont(f); }
        lbl->setStyleSheet("color:#333;");
        form->addRow("<b>" + key + "</b>", lbl);
    };

    // 攻击进程信息
    auto *gbProc = makeSection("攻击进程信息");
    auto *formProc = new QFormLayout(gbProc);
    formProc->setSpacing(8);
    addKV(formProc, "进程路径",      rec["proc_path"].toString(), true);
    addKV(formProc, "进程标识(PID)", rec["pid"].toString());
    addKV(formProc, "工具名称",      rec["tool_name"].toString(), false, true);
    addKV(formProc, "描述信息",      rec["description"].toString());
    addKV(formProc, "检测时间",      rec["detect_time"].toString());
    mainLay->addWidget(gbProc);

    // 网络连接信息（五元组）
    auto *gbNet = makeSection("网络连接信息（五元组）");
    auto *formNet = new QFormLayout(gbNet);
    formNet->setSpacing(8);
    addKV(formNet, "源IP地址",   rec["src_ip"].toString(), true);
    addKV(formNet, "源端口",     rec["src_port"].toString());
    addKV(formNet, "目的IP地址", rec["dst_ip"].toString(), true);
    addKV(formNet, "目的端口",   rec["dst_port"].toString());
    addKV(formNet, "协议类型",   rec["protocol"].toString(), false, true);
    mainLay->addWidget(gbNet);

    // 所利用的系统漏洞
    auto *gbVuln = makeSection("所利用的系统漏洞");
    auto *formVuln = new QFormLayout(gbVuln);
    formVuln->setSpacing(8);

    auto *lblCve = new QLabel(rec["cve_id"].toString());
    lblCve->setStyleSheet("color:#1890ff;font-weight:700;font-size:13px;");
    formVuln->addRow("<b>漏洞编号</b>", lblCve);

    addKV(formVuln, "发布时间", rec["cve_publish"].toString());

    double cvss = rec["cvss_score"].toDouble();
    QColor cvssColor = cvss >= 9.0 ? QColor("#f5222d") : cvss >= 7.0 ? QColor("#fa8c16") : QColor("#1890ff");
    auto *lblCvss = new QLabel(QString::number(cvss, 'f', 1));
    lblCvss->setStyleSheet(QString("color:%1;font-weight:700;font-size:13px;").arg(cvssColor.name()));
    formVuln->addRow("<b>CVSS评分</b>", lblCvss);

    addKV(formVuln, "影响组件", rec["vuln_component"].toString(), false, true);

    auto *lblDesc = new QLabel(rec["vuln_desc"].toString());
    lblDesc->setWordWrap(true);
    lblDesc->setStyleSheet("color:#333;background:#f8f9fb;padding:8px;border-radius:3px;"
                           "border:1px solid #e0e6f0;");
    formVuln->addRow("<b>漏洞描述</b>", lblDesc);
    mainLay->addWidget(gbVuln);

    auto *btnClose = new QPushButton("关闭");
    btnClose->setStyleSheet(
        "QPushButton{background:#1a3a6a;color:#fff;border:none;"
        "border-radius:3px;padding:6px 24px;font-size:12px;}"
        "QPushButton:hover{background:#2a5a9a;}");
    auto *btnRow = new QHBoxLayout;
    btnRow->addStretch();
    btnRow->addWidget(btnClose);
    mainLay->addLayout(btnRow);
    connect(btnClose, &QPushButton::clicked, &dlg, &QDialog::accept);

    dlg.exec();
}

void VulnDetectPage::onExport()
{
    QString path = QFileDialog::getSaveFileName(this, "导出漏洞报告", "vuln_report.csv",
        "CSV文件 (*.csv)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "错误", "无法创建文件！"); return;
    }
    QTextStream ts(&f);
    ts.setCodec("UTF-8");
    ts << "\xEF\xBB\xBF";
    ts << "进程路径,PID,工具名称,描述,源IP,源端口,目的IP,目的端口,协议,威胁等级,CVE编号,发布时间,CVSS,漏洞描述\n";
    for (const QVariantMap &m : m_dataCache) {
        ts << "\"" << m["proc_path"].toString() << "\","
           << m["pid"].toString() << ","
           << "\"" << m["tool_name"].toString() << "\","
           << "\"" << m["description"].toString() << "\","
           << m["src_ip"].toString() << ","
           << m["src_port"].toString() << ","
           << m["dst_ip"].toString() << ","
           << m["dst_port"].toString() << ","
           << m["protocol"].toString() << ","
           << m["risk_level"].toString() << ","
           << m["cve_id"].toString() << ","
           << m["cve_publish"].toString() << ","
           << m["cvss_score"].toString() << ","
           << "\"" << m["vuln_desc"].toString() << "\"\n";
    }
    f.close();
    DatabaseManager::instance()->writeLog(m_role, m_username, "漏洞监测", "导出漏洞报告：" + path, "success");
    QMessageBox::information(this, "提示", "导出成功！\n" + path);
}
