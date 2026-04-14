#include "pages/StaticScanPage.h"
#include "DatabaseManager.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QSplitter>
#include <QFileDialog>
#include <QSqlQuery>
#include <QSqlDatabase>
#include <QGroupBox>
#include <QHeaderView>
#include <QFormLayout>
#include <QFrame>
#include <QFileInfo>
#include <QDateTime>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

// ─────────────────────────────────────────────────────────────────────────────
// 辅助：创建属性行标签（左侧 key，右侧 value）
// ─────────────────────────────────────────────────────────────────────────────
static QLabel* makeAttrValue(const QString &placeholder = "--")
{
    QLabel *lbl = new QLabel(placeholder);
    lbl->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lbl->setWordWrap(true);
    return lbl;
}

// ─────────────────────────────────────────────────────────────────────────────
StaticScanPage::StaticScanPage(QWidget *parent)
    : BasePage("静态检测", parent)
{
    setupUi();
    populateFileList();
}

void StaticScanPage::refreshData()
{
    populateFileList();
}

// ─────────────────────────────────────────────────────────────────────────────
// setupUi：整体为水平 Splitter（左侧文件列表 | 右侧详情区）
// ─────────────────────────────────────────────────────────────────────────────
void StaticScanPage::setupUi()
{
    QSplitter *hSplitter = new QSplitter(Qt::Horizontal);
    hSplitter->setChildrenCollapsible(false);

    // ══════════════════════════════════════════════════════
    // 左侧：文件列表面板
    // ══════════════════════════════════════════════════════
    QWidget *leftPanel = new QWidget;
    QVBoxLayout *leftLayout = new QVBoxLayout(leftPanel);
    leftLayout->setContentsMargins(0, 0, 4, 0);
    leftLayout->setSpacing(4);

    QLabel *listTitle = new QLabel("待检测文件列表");
    listTitle->setObjectName("sectionTitle");
    listTitle->setStyleSheet("font-weight:bold; font-size:13px; padding:4px 0;");
    leftLayout->addWidget(listTitle);

    m_fileList = new QListWidget;
    m_fileList->setObjectName("fileListWidget");
    m_fileList->setAlternatingRowColors(true);
    m_fileList->setSelectionMode(QAbstractItemView::SingleSelection);
    m_fileList->setStyleSheet(
        "QListWidget { border:1px solid #c0c0c0; background:#fff; font-size:12px; }"
        "QListWidget::item { padding:5px 6px; border-bottom:1px solid #ececec; }"
        "QListWidget::item:selected { background:#1565c0; color:#fff; }"
        "QListWidget::item:hover { background:#e3f2fd; }"
    );
    connect(m_fileList, &QListWidget::itemClicked,
            this, &StaticScanPage::onFileItemClicked);
    leftLayout->addWidget(m_fileList, 1);

    // 文件列表操作按钮行
    QHBoxLayout *listBtnRow = new QHBoxLayout;
    listBtnRow->setSpacing(4);
    m_btnAddFile = new QPushButton("添加文件");
    m_btnAddFile->setObjectName("btnPrimary");
    m_btnRemoveFile = new QPushButton("移除");
    m_btnRemoveFile->setObjectName("btnSecondary");
    m_btnScanSelected = new QPushButton("检测选中");
    m_btnScanSelected->setObjectName("btnPrimary");
    m_btnScanAll = new QPushButton("全部检测");
    m_btnScanAll->setObjectName("btnSecondary");
    listBtnRow->addWidget(m_btnAddFile);
    listBtnRow->addWidget(m_btnRemoveFile);
    listBtnRow->addStretch();
    listBtnRow->addWidget(m_btnScanSelected);
    listBtnRow->addWidget(m_btnScanAll);
    leftLayout->addLayout(listBtnRow);

    connect(m_btnAddFile,      &QPushButton::clicked, this, &StaticScanPage::onAddFile);
    connect(m_btnRemoveFile,   &QPushButton::clicked, this, &StaticScanPage::onRemoveFile);
    connect(m_btnScanSelected, &QPushButton::clicked, this, &StaticScanPage::onScanSelected);
    connect(m_btnScanAll,      &QPushButton::clicked, this, &StaticScanPage::onScanAll);

    hSplitter->addWidget(leftPanel);

    // ══════════════════════════════════════════════════════
    // 右侧：垂直 Splitter（上：基本属性 | 下：详情Tab）
    // ══════════════════════════════════════════════════════
    QSplitter *vSplitter = new QSplitter(Qt::Vertical);
    vSplitter->setChildrenCollapsible(false);

    // ── 上方：基本属性面板 ──────────────────────────────
    QGroupBox *attrBox = new QGroupBox("基本属性");
    attrBox->setStyleSheet("QGroupBox { font-weight:bold; font-size:13px; }");
    setupAttrPanel(attrBox);
    vSplitter->addWidget(attrBox);

    // ── 下方：详情 Tab ──────────────────────────────────
    m_tabDetail = new QTabWidget;
    m_tabDetail->setObjectName("detailTab");

    // Tab 1: PE 结构
    m_txtPeInfo = new QTextEdit;
    m_txtPeInfo->setReadOnly(true);
    m_txtPeInfo->setObjectName("codeView");
    m_txtPeInfo->setPlaceholderText("点击左侧文件列表中的文件，查看 PE 结构信息...");
    m_tabDetail->addTab(m_txtPeInfo, "PE 结构");

    // Tab 2: 字符串提取
    m_txtStrings = new QTextEdit;
    m_txtStrings->setReadOnly(true);
    m_txtStrings->setObjectName("codeView");
    m_txtStrings->setPlaceholderText("点击左侧文件列表中的文件，查看提取的可疑字符串...");
    m_tabDetail->addTab(m_txtStrings, "字符串提取");

    // Tab 3: 规则命中
    m_txtRules = new QTextEdit;
    m_txtRules->setReadOnly(true);
    m_txtRules->setObjectName("codeView");
    m_txtRules->setPlaceholderText("点击左侧文件列表中的文件，查看规则命中详情...");
    m_tabDetail->addTab(m_txtRules, "规则命中");

    // Tab 4: 数字证书（从 CertScanPage 迁移）
    m_txtCert = new QTextEdit;
    m_txtCert->setReadOnly(true);
    m_txtCert->setObjectName("codeView");
    m_txtCert->setPlaceholderText("点击左侧文件列表中的文件，查看数字证书信息...");
    m_tabDetail->addTab(m_txtCert, "数字证书");

    // Tab 5: 综合结论
    m_txtConclusion = new QTextEdit;
    m_txtConclusion->setReadOnly(true);
    m_txtConclusion->setObjectName("codeView");
    m_txtConclusion->setPlaceholderText("点击左侧文件列表中的文件，查看综合检测结论...");
    m_tabDetail->addTab(m_txtConclusion, "综合结论");

    vSplitter->addWidget(m_tabDetail);
    vSplitter->setStretchFactor(0, 2);
    vSplitter->setStretchFactor(1, 3);

    hSplitter->addWidget(vSplitter);
    hSplitter->setStretchFactor(0, 1);  // 左侧文件列表
    hSplitter->setStretchFactor(1, 3);  // 右侧详情区

    m_mainLayout->addWidget(hSplitter, 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// setupAttrPanel：基本属性面板，使用 QFormLayout 排列
// ─────────────────────────────────────────────────────────────────────────────
void StaticScanPage::setupAttrPanel(QWidget *parent)
{
    QFormLayout *form = new QFormLayout(parent);
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->setHorizontalSpacing(12);
    form->setVerticalSpacing(6);
    form->setContentsMargins(12, 16, 12, 8);

    m_attrFileName  = makeAttrValue("--");
    m_attrFilePath  = makeAttrValue("--");
    m_attrFileSize  = makeAttrValue("--");
    m_attrFileType  = makeAttrValue("--");
    m_attrMd5       = makeAttrValue("--");
    m_attrSha256    = makeAttrValue("--");
    m_attrScanTime  = makeAttrValue("--");

    // 风险等级标签
    m_attrRiskLevel = makeAttrValue("--");
    m_attrRiskLevel->setStyleSheet("font-weight:bold;");

    // 病毒检测状态标签
    m_attrVirusStatus = makeAttrValue("--");
    m_attrVirusStatus->setStyleSheet("font-weight:bold; font-size:13px;");

    // 病毒名称（威胁时显示）
    m_attrVirusName = makeAttrValue("--");
    m_attrVirusName->setStyleSheet("color:#c62828;");

    form->addRow("文件名：",    m_attrFileName);
    form->addRow("文件路径：",  m_attrFilePath);
    form->addRow("文件大小：",  m_attrFileSize);
    form->addRow("文件类型：",  m_attrFileType);
    form->addRow("MD5：",       m_attrMd5);
    form->addRow("SHA256：",    m_attrSha256);
    form->addRow("扫描时间：",  m_attrScanTime);

    // 分隔线
    QFrame *line = new QFrame;
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    form->addRow(line);

    form->addRow("风险等级：",  m_attrRiskLevel);
    form->addRow("病毒检测：",  m_attrVirusStatus);
    form->addRow("病毒名称：",  m_attrVirusName);
}

// ─────────────────────────────────────────────────────────────────────────────
// populateFileList：从 static_scan 表加载已检测文件列表
// ─────────────────────────────────────────────────────────────────────────────
void StaticScanPage::populateFileList()
{
    m_fileList->clear();

    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.exec("SELECT id, file_name, file_path, risk_level, scan_time "
               "FROM static_scan ORDER BY id DESC LIMIT 200");
        while (q.next()) {
            int    id        = q.value(0).toInt();
            QString name     = q.value(1).toString();
            QString path     = q.value(2).toString();
            QString risk     = q.value(3).toString();
            QString scanTime = q.value(4).toString();

            // 显示文本：文件名 + 风险等级标记
            QString riskTag;
            if      (risk == "high")   riskTag = " [高危]";
            else if (risk == "medium") riskTag = " [中危]";
            else if (risk == "low")    riskTag = " [低危]";
            else if (risk == "clean")  riskTag = " [安全]";

            QListWidgetItem *item = new QListWidgetItem(name + riskTag);
            item->setData(Qt::UserRole,     id);
            item->setData(Qt::UserRole + 1, path);
            item->setData(Qt::UserRole + 2, risk);
            item->setToolTip(path + "\n扫描时间：" + scanTime);

            // 颜色标记
            if      (risk == "high")   item->setForeground(QColor("#c62828"));
            else if (risk == "medium") item->setForeground(QColor("#e65100"));
            else if (risk == "low")    item->setForeground(QColor("#1565c0"));
            else if (risk == "clean")  item->setForeground(QColor("#2e7d32"));

            m_fileList->addItem(item);
        }
    }

    // 若数据库无数据，显示演示条目
    if (m_fileList->count() == 0) {
        struct DemoFile { QString name; QString path; QString risk; };
        QList<DemoFile> demos = {
            {"suspicious.exe",
             "C:\\Users\\admin\\AppData\\Roaming\\suspicious.exe", "high"},
            {"invoice_2025.pdf.exe",
             "C:\\Users\\admin\\Desktop\\invoice_2025.pdf.exe",    "high"},
            {"svch0st.exe",
             "C:\\Windows\\Temp\\svch0st.exe",                     "medium"},
            {"chrome.exe",
             "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "clean"},
            {"ntdll.dll",
             "C:\\Windows\\System32\\ntdll.dll",                   "clean"},
        };
        for (const DemoFile &d : demos) {
            QString riskTag;
            if      (d.risk == "high")   riskTag = " [高危]";
            else if (d.risk == "medium") riskTag = " [中危]";
            else if (d.risk == "clean")  riskTag = " [安全]";

            QListWidgetItem *item = new QListWidgetItem(d.name + riskTag);
            item->setData(Qt::UserRole,     -1);
            item->setData(Qt::UserRole + 1, d.path);
            item->setData(Qt::UserRole + 2, d.risk);
            item->setToolTip(d.path);

            if      (d.risk == "high")   item->setForeground(QColor("#c62828"));
            else if (d.risk == "medium") item->setForeground(QColor("#e65100"));
            else if (d.risk == "clean")  item->setForeground(QColor("#2e7d32"));

            m_fileList->addItem(item);
        }
    }

    m_lblStatus->setText(QString("文件列表：共 %1 个文件").arg(m_fileList->count()));
}

// ─────────────────────────────────────────────────────────────────────────────
// onFileItemClicked：点击文件列表项，加载该文件的详情
// ─────────────────────────────────────────────────────────────────────────────
void StaticScanPage::onFileItemClicked(QListWidgetItem *item)
{
    if (!item) return;
    int     id   = item->data(Qt::UserRole).toInt();
    QString path = item->data(Qt::UserRole + 1).toString();
    loadFileDetail(id, path);
}

// ─────────────────────────────────────────────────────────────────────────────
// loadFileDetail：从数据库加载并展示文件详情
// ─────────────────────────────────────────────────────────────────────────────
void StaticScanPage::loadFileDetail(int staticId, const QString &filePath)
{
    clearDetail();

    QSqlDatabase db = QSqlDatabase::database("main_conn");

    // ── 从 static_scan 加载基本属性 + 检测结果 ──────────────
    if (staticId > 0 && db.isOpen()) {
        QSqlQuery q(db);
        q.prepare("SELECT file_name, file_path, file_size, file_type, md5, sha256, "
                  "       pe_info, strings_info, rule_hits, risk_level, conclusion, "
                  "       scan_time, virus_name "
                  "FROM static_scan WHERE id = ?");
        q.addBindValue(staticId);
        if (q.exec() && q.next()) {
            // 基本属性
            m_attrFileName->setText(q.value(0).toString());
            m_attrFilePath->setText(q.value(1).toString());
            qint64 sz = q.value(2).toLongLong();
            m_attrFileSize->setText(sz > 0 ?
                QString("%1 KB (%2 字节)").arg(sz/1024).arg(sz) : "--");
            m_attrFileType->setText(q.value(3).toString().isEmpty() ? "--" : q.value(3).toString());
            m_attrMd5->setText(q.value(4).toString().isEmpty() ? "--" : q.value(4).toString());
            m_attrSha256->setText(q.value(5).toString().isEmpty() ? "--" : q.value(5).toString());
            m_attrScanTime->setText(q.value(11).toString().isEmpty() ? "--" : q.value(11).toString());

            // 风险等级
            QString risk = q.value(9).toString();
            QString riskText;
            QString riskColor;
            if      (risk == "high")   { riskText = "高危"; riskColor = "#c62828"; }
            else if (risk == "medium") { riskText = "中危"; riskColor = "#e65100"; }
            else if (risk == "low")    { riskText = "低危"; riskColor = "#1565c0"; }
            else if (risk == "clean")  { riskText = "正常"; riskColor = "#2e7d32"; }
            else                       { riskText = "--";   riskColor = "#555555"; }
            m_attrRiskLevel->setText(riskText);
            m_attrRiskLevel->setStyleSheet(
                QString("font-weight:bold; font-size:13px; color:%1;").arg(riskColor));

            // 病毒检测项
            QString virusName = q.value(12).toString();
            if (!virusName.isEmpty() && virusName != "安全" && risk != "clean") {
                m_attrVirusStatus->setText("威胁");
                m_attrVirusStatus->setStyleSheet(
                    "font-weight:bold; font-size:13px; color:#c62828; "
                    "background:#ffebee; padding:2px 8px; border-radius:3px;");
                m_attrVirusName->setText(virusName);
                m_attrVirusName->setStyleSheet("color:#c62828; font-weight:bold;");
            } else if (risk == "clean") {
                m_attrVirusStatus->setText("安全");
                m_attrVirusStatus->setStyleSheet(
                    "font-weight:bold; font-size:13px; color:#2e7d32; "
                    "background:#e8f5e9; padding:2px 8px; border-radius:3px;");
                m_attrVirusName->setText("--");
                m_attrVirusName->setStyleSheet("color:#888;");
            } else {
                // 有风险但无具体病毒名，从结论推断
                m_attrVirusStatus->setText("威胁");
                m_attrVirusStatus->setStyleSheet(
                    "font-weight:bold; font-size:13px; color:#c62828; "
                    "background:#ffebee; padding:2px 8px; border-radius:3px;");
                m_attrVirusName->setText("未知威胁（待引擎识别）");
                m_attrVirusName->setStyleSheet("color:#c62828;");
            }

            // 详情 Tab 内容
            QString peInfo = q.value(6).toString();
            m_txtPeInfo->setPlainText(peInfo.isEmpty() ? "（PE结构数据待检测引擎填充）" : peInfo);

            QString strings = q.value(7).toString();
            m_txtStrings->setPlainText(strings.isEmpty() ? "（字符串数据待检测引擎填充）" : strings);

            QString rules = q.value(8).toString();
            // 尝试解析 JSON 格式的规则命中
            if (!rules.isEmpty()) {
                QJsonDocument doc = QJsonDocument::fromJson(rules.toUtf8());
                if (doc.isArray()) {
                    QJsonArray arr = doc.array();
                    QString formatted = "[规则命中列表]\n";
                    for (const QJsonValue &v : arr) {
                        QJsonObject obj = v.toObject();
                        formatted += QString("  [%1] %2: %3\n")
                            .arg(obj["severity"].toString().toUpper())
                            .arg(obj["rule"].toString())
                            .arg(obj["match"].toString());
                    }
                    m_txtRules->setPlainText(formatted);
                } else {
                    m_txtRules->setPlainText(rules);
                }
            } else {
                m_txtRules->setPlainText("（规则命中数据待检测引擎填充）");
            }

            m_txtConclusion->setPlainText(
                q.value(10).toString().isEmpty() ?
                "（综合结论待检测引擎填充）" : q.value(10).toString());
        }
    } else {
        // 演示数据：根据文件名填充示例内容
        QFileInfo fi(filePath);
        m_attrFileName->setText(fi.fileName());
        m_attrFilePath->setText(filePath);
        m_attrFileSize->setText("--（未检测）");
        m_attrFileType->setText("--");
        m_attrMd5->setText("--（未检测）");
        m_attrSha256->setText("--（未检测）");
        m_attrScanTime->setText("--");
        m_attrRiskLevel->setText("--");
        m_attrRiskLevel->setStyleSheet("font-weight:bold; font-size:13px; color:#555;");
        m_attrVirusStatus->setText("--");
        m_attrVirusStatus->setStyleSheet("font-weight:bold; font-size:13px; color:#555;");
        m_attrVirusName->setText("--");

        m_txtPeInfo->setPlainText("请点击[\u68c0\u6d4b\u9009\u4e2d]对该文件执行静态检测...");
        m_txtStrings->setPlainText("请点击[\u68c0\u6d4b\u9009\u4e2d]对该文件执行静态检测...");
        m_txtRules->setPlainText("请点击[\u68c0\u6d4b\u9009\u4e2d]对该文件执行静态检测...");
        m_txtCert->setPlainText("请点击[\u68c0\u6d4b\u9009\u4e2d]对该文件执行静态检测...");
        m_txtConclusion->setPlainText("请点击[\u68c0\u6d4b\u9009\u4e2d]对该文件执行静态检测...");
        return;
    }

    // ── 从 cert_scan 加载数字证书信息 ────────────────────────
    if (db.isOpen()) {
        QSqlQuery cq(db);
        cq.prepare("SELECT has_signature, signature_valid, file_tampered, "
                   "       subject, issuer, serial_number, not_before, not_after, "
                   "       not_expired, hash_algorithm, thumbprint_sha1, verify_result "
                   "FROM cert_scan WHERE file_path = ? ORDER BY id DESC LIMIT 1");
        cq.addBindValue(filePath);
        if (cq.exec() && cq.next()) {
            bool hasSig    = cq.value(0).toInt() == 1;
            bool sigValid  = cq.value(1).toInt() == 1;
            bool tampered  = cq.value(2).toInt() == 1;
            bool notExpired= cq.value(8).toInt() == 1;
            QString subject    = cq.value(3).toString();
            QString issuer     = cq.value(4).toString();
            QString serial     = cq.value(5).toString();
            QString notBefore  = cq.value(6).toString();
            QString notAfter   = cq.value(7).toString();
            QString hashAlg    = cq.value(9).toString();
            QString thumbSha1  = cq.value(10).toString();
            QString verifyResult = cq.value(11).toString();

            QString certText;
            certText += "═══════════════════════════════════════\n";
            certText += "  数字证书检测结果\n";
            certText += "═══════════════════════════════════════\n\n";
            certText += QString("  是否有签名：  %1\n").arg(hasSig ? "是" : "否");
            if (hasSig) {
                certText += QString("  签名有效性：  %1\n").arg(sigValid ? "✓ 有效" : "✗ 无效");
                certText += QString("  证书有效期：  %1\n").arg(notExpired ? "✓ 未过期" : "✗ 已过期");
                certText += QString("  文件完整性：  %1\n").arg(!tampered ? "✓ 未被篡改" : "✗ 文件已被篡改");
                certText += "\n";
                certText += QString("  签名者：      %1\n").arg(subject.isEmpty() ? "--" : subject);
                certText += QString("  颁发机构：    %1\n").arg(issuer.isEmpty()  ? "--" : issuer);
                certText += QString("  序列号：      %1\n").arg(serial.isEmpty()  ? "--" : serial);
                certText += QString("  有效期起：    %1\n").arg(notBefore.isEmpty()? "--" : notBefore);
                certText += QString("  有效期止：    %1\n").arg(notAfter.isEmpty() ? "--" : notAfter);
                certText += QString("  哈希算法：    %1\n").arg(hashAlg.isEmpty() ? "--" : hashAlg);
                certText += QString("  指纹(SHA1)：  %1\n").arg(thumbSha1.isEmpty()? "--" : thumbSha1);
            }
            certText += "\n";
            certText += QString("  验证结论：    %1\n").arg(verifyResult.isEmpty() ? "--" : verifyResult);
            m_txtCert->setPlainText(certText);
        } else {
            // 无证书记录
            m_txtCert->setPlainText(
                "═══════════════════════════════════════\n"
                "  数字证书检测结果\n"
                "═══════════════════════════════════════\n\n"
                "  该文件暂无数字证书检测记录。\n"
                "  请执行静态检测后查看证书信息。\n"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// clearDetail：清空右侧所有详情区
// ─────────────────────────────────────────────────────────────────────────────
void StaticScanPage::clearDetail()
{
    m_attrFileName->setText("--");
    m_attrFilePath->setText("--");
    m_attrFileSize->setText("--");
    m_attrFileType->setText("--");
    m_attrMd5->setText("--");
    m_attrSha256->setText("--");
    m_attrScanTime->setText("--");
    m_attrRiskLevel->setText("--");
    m_attrRiskLevel->setStyleSheet("font-weight:bold; font-size:13px; color:#555;");
    m_attrVirusStatus->setText("--");
    m_attrVirusStatus->setStyleSheet("font-weight:bold; font-size:13px; color:#555;");
    m_attrVirusName->setText("--");
    m_attrVirusName->setStyleSheet("color:#888;");
    m_txtPeInfo->clear();
    m_txtStrings->clear();
    m_txtRules->clear();
    m_txtCert->clear();
    m_txtConclusion->clear();
}

// ─────────────────────────────────────────────────────────────────────────────
// addFileToList：将文件路径添加到列表（去重）
// ─────────────────────────────────────────────────────────────────────────────
void StaticScanPage::addFileToList(const QString &path)
{
    if (path.isEmpty()) return;
    // 检查是否已存在
    for (int i = 0; i < m_fileList->count(); ++i) {
        if (m_fileList->item(i)->data(Qt::UserRole + 1).toString() == path)
            return;
    }
    QFileInfo fi(path);
    QListWidgetItem *item = new QListWidgetItem(fi.fileName() + " [待检测]");
    item->setData(Qt::UserRole,     -1);
    item->setData(Qt::UserRole + 1, path);
    item->setData(Qt::UserRole + 2, "unknown");
    item->setToolTip(path);
    item->setForeground(QColor("#555555"));
    m_fileList->addItem(item);
    m_fileList->setCurrentItem(item);
    m_lblStatus->setText("已添加：" + fi.fileName());
}

// ─────────────────────────────────────────────────────────────────────────────
// Slots
// ─────────────────────────────────────────────────────────────────────────────
void StaticScanPage::onAddFile()
{
    QStringList paths = QFileDialog::getOpenFileNames(
        this, "选择文件", "", "所有文件 (*.*);;可执行文件 (*.exe *.dll *.sys)");
    for (const QString &p : paths)
        addFileToList(p);
}

void StaticScanPage::onRemoveFile()
{
    QListWidgetItem *cur = m_fileList->currentItem();
    if (!cur) { m_lblStatus->setText("请先选择要移除的文件"); return; }
    QString name = cur->text();
    delete cur;
    clearDetail();
    m_lblStatus->setText("已移除：" + name);
}

void StaticScanPage::onScanSelected()
{
    QListWidgetItem *cur = m_fileList->currentItem();
    if (!cur) { m_lblStatus->setText("请先在左侧列表中选择文件"); return; }

    QString path = cur->data(Qt::UserRole + 1).toString();
    QFileInfo fi(path);
    m_lblStatus->setText("正在检测：" + fi.fileName() + " ...");

    // 写入占位检测记录（实际由检测引擎填充）
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.prepare("INSERT INTO static_scan(file_path, file_name, file_type, file_size, "
                  "md5, sha256, risk_level, conclusion) VALUES(?,?,?,?,?,?,?,?)");
        q.addBindValue(path);
        q.addBindValue(fi.fileName());
        q.addBindValue("PE32");
        q.addBindValue(fi.size());
        q.addBindValue("（待检测引擎填充）");
        q.addBindValue("（待检测引擎填充）");
        q.addBindValue("unknown");
        q.addBindValue("已提交检测，等待引擎结果");
        q.exec();
        DatabaseManager::instance()->writeLog(
            m_role, m_username, "静态检测",
            "提交文件：" + fi.fileName(), "success");
    }
    populateFileList();
    m_lblStatus->setText("已提交检测：" + fi.fileName());
}

void StaticScanPage::onScanAll()
{
    if (m_fileList->count() == 0) {
        m_lblStatus->setText("文件列表为空，请先添加文件");
        return;
    }
    m_lblStatus->setText(QString("已提交全部 %1 个文件进行检测...").arg(m_fileList->count()));
    DatabaseManager::instance()->writeLog(
        m_role, m_username, "静态检测",
        QString("批量提交 %1 个文件").arg(m_fileList->count()), "success");
}
