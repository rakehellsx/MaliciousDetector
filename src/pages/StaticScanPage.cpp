#include "pages/StaticScanPage.h"
#include "ui_StaticScanPage.h"

#include "DatabaseManager.h"
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QFileDialog>
#include <QFileInfo>
#include <QHeaderView>
#include <QFormLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QFont>
#include <QScrollArea>
#include <QSizePolicy>
#include <QGroupBox>
#include <QFrame>
#include <QDateTime>

static QLabel *makeAttrValue(const QString &placeholder = "--")
{
    QLabel *lbl = new QLabel(placeholder);
    lbl->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lbl->setWordWrap(true);
    return lbl;
}

QLabel *StaticScanPage::makeBadge(const QString &text, const QString &bg,
                                   const QString &fg, QWidget *parent)
{
    QLabel *lbl = new QLabel(text, parent);
    lbl->setAlignment(Qt::AlignCenter);
    lbl->setStyleSheet(QString(
        "QLabel { background:%1; color:%2; border-radius:4px; padding:2px 10px;"
        " font-weight:bold; font-size:12px; }").arg(bg, fg));
    lbl->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    return lbl;
}

StaticScanPage::StaticScanPage(QWidget *parent)
    : BasePage("静态检测", parent)
{
    ui = new Ui::StaticScanPage();
    ui->setupUi(this);
    postSetupUi();
    m_fileList = ui->m_fileList;
    m_btnAddFile = ui->m_btnAddFile;
    m_btnRemoveFile = ui->m_btnRemoveFile;
    m_btnScanSelected = ui->m_btnScanSelected;
    m_btnScanAll = ui->m_btnScanAll;
    m_edtFileKw = ui->m_edtFileKw;
    m_cmbFileRisk = ui->m_cmbFileRisk;
    m_attrFileName = ui->m_attrFileName;
    m_attrFilePath = ui->m_attrFilePath;
    m_attrFileSize = ui->m_attrFileSize;
    m_attrFileType = ui->m_attrFileType;
    m_attrMd5 = ui->m_attrMd5;
    m_attrSha256 = ui->m_attrSha256;
    m_attrScanTime = ui->m_attrScanTime;
    m_attrRiskLevel = ui->m_attrRiskLevel;
    m_attrVirusStatus = ui->m_attrVirusStatus;
    m_attrVirusName = ui->m_attrVirusName;
    m_tabDetail = ui->m_tabDetail;
    m_treePe = ui->m_treePe;
    m_edtStrKw = ui->m_edtStrKw;
    m_cmbStrType = ui->m_cmbStrType;
    m_tblStrings = ui->m_tblStrings;
    m_edtRuleKw = ui->m_edtRuleKw;
    m_cmbRuleRisk = ui->m_cmbRuleRisk;
    m_tblRules = ui->m_tblRules;
    m_edtCertKw = ui->m_edtCertKw;
    m_cmbCertStatus = ui->m_cmbCertStatus;
    m_certStatusBadge = ui->m_certStatusBadge;
    m_certSignedBadge = ui->m_certSignedBadge;
    m_certExpiredBadge = ui->m_certExpiredBadge;
    m_certTamperedBadge = ui->m_certTamperedBadge;
    m_certSubject = ui->m_certSubject;
    m_certIssuer = ui->m_certIssuer;
    m_certSerial = ui->m_certSerial;
    m_certNotBefore = ui->m_certNotBefore;
    m_certNotAfter = ui->m_certNotAfter;
    m_certHashAlg = ui->m_certHashAlg;
    m_certThumbprint = ui->m_certThumbprint;
    m_certVerifyResult = ui->m_certVerifyResult;
    m_concRiskCard = ui->m_concRiskCard;
    m_concRiskIcon = ui->m_concRiskIcon;
    m_concRiskText = ui->m_concRiskText;
    m_concVirusName = ui->m_concVirusName;
    m_concText = ui->m_concText;
    populateFileList();
}

void StaticScanPage::refreshData() { populateFileList(); }

void StaticScanPage::setupAttrPanel(QWidget *parent)
{
    QFormLayout *form = new QFormLayout(parent);
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->setHorizontalSpacing(12);
    form->setVerticalSpacing(6);
    form->setContentsMargins(12, 16, 12, 8);

    m_attrFileName    = makeAttrValue("--");
    m_attrFilePath    = makeAttrValue("--");
    m_attrFileSize    = makeAttrValue("--");
    m_attrFileType    = makeAttrValue("--");
    m_attrMd5         = makeAttrValue("--");
    m_attrSha256      = makeAttrValue("--");
    m_attrScanTime    = makeAttrValue("--");
    m_attrRiskLevel   = makeAttrValue("--");
    m_attrRiskLevel->setStyleSheet("font-weight:bold;");
    m_attrVirusStatus = makeAttrValue("--");
    m_attrVirusStatus->setStyleSheet("font-weight:bold; font-size:13px;");
    m_attrVirusName   = makeAttrValue("--");
    m_attrVirusName->setStyleSheet("color:#c62828;");

    form->addRow("文件名：",   m_attrFileName);
    form->addRow("文件路径：", m_attrFilePath);
    form->addRow("文件大小：", m_attrFileSize);
    form->addRow("文件类型：", m_attrFileType);
    form->addRow("MD5：",      m_attrMd5);
    form->addRow("SHA256：",   m_attrSha256);
    form->addRow("扫描时间：", m_attrScanTime);
    QFrame *line = new QFrame;
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    form->addRow(line);
    form->addRow("风险等级：", m_attrRiskLevel);
    form->addRow("病毒检测：", m_attrVirusStatus);
    form->addRow("病毒名称：", m_attrVirusName);
}

QWidget *StaticScanPage::buildPeTab()
{
    QWidget *w = new QWidget;
    QVBoxLayout *lay = new QVBoxLayout(w);
    lay->setContentsMargins(4, 4, 4, 4);
    lay->setSpacing(4);
    QLabel *hint = new QLabel("PE 文件结构树形视图（节头 / 导入表 / 导出表 / 节区列表）");
    hint->setStyleSheet("color:#666; font-size:11px; padding:2px 4px;");
    lay->addWidget(hint);
    m_treePe = new QTreeWidget;
    m_treePe->setColumnCount(2);
    m_treePe->setHeaderLabels({"字段", "值"});
    m_treePe->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_treePe->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_treePe->setAlternatingRowColors(true);
    m_treePe->setRootIsDecorated(true);
    m_treePe->setExpandsOnDoubleClick(true);
    m_treePe->setStyleSheet(
        "QTreeWidget { border:1px solid #ddd; border-radius:4px; font-size:12px; }"
        "QTreeWidget::item { padding:3px 4px; }"
        "QTreeWidget::item:selected { background:#1565c0; color:#fff; }");
    lay->addWidget(m_treePe, 1);
    return w;
}

QWidget *StaticScanPage::buildStringsTab()
{
    QWidget *w = new QWidget;
    QVBoxLayout *lay = new QVBoxLayout(w);
    lay->setContentsMargins(4, 4, 4, 4);
    lay->setSpacing(4);
    QLabel *hint = new QLabel("从 PE 文件中提取的可疑字符串（URL / IP / API / 路径 / 其他）");
    hint->setStyleSheet("color:#666; font-size:11px; padding:2px 4px;");
    lay->addWidget(hint);

    // 字符串查询栏
    QHBoxLayout *strQueryRow = new QHBoxLayout;
    strQueryRow->setSpacing(6);
    m_edtStrKw = new QLineEdit;
    m_edtStrKw->setPlaceholderText("字符串内容关键字");
    m_edtStrKw->setClearButtonEnabled(true);
    m_edtStrKw->setFixedWidth(200);
    connect(m_edtStrKw, &QLineEdit::returnPressed, this, &StaticScanPage::onQueryStrings);
    m_cmbStrType = new QComboBox;
    m_cmbStrType->addItems({"全部类型", "URL", "IP", "API", "路径", "命令", "其他"});
    connect(m_cmbStrType, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &StaticScanPage::onQueryStrings);
    QPushButton *btnStrQuery = new QPushButton("查询");
    btnStrQuery->setObjectName("btnPrimary");
    btnStrQuery->setFixedWidth(70);
    connect(btnStrQuery, &QPushButton::clicked, this, &StaticScanPage::onQueryStrings);
    strQueryRow->addWidget(new QLabel("关键字："));
    strQueryRow->addWidget(m_edtStrKw);
    strQueryRow->addSpacing(8);
    strQueryRow->addWidget(new QLabel("类型："));
    strQueryRow->addWidget(m_cmbStrType);
    strQueryRow->addWidget(btnStrQuery);
    strQueryRow->addStretch();
    lay->addLayout(strQueryRow);

    m_tblStrings = new QTableWidget(0, 3);
    m_tblStrings->setHorizontalHeaderLabels({"偏移量", "类型", "字符串内容"});
    m_tblStrings->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_tblStrings->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_tblStrings->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_tblStrings->verticalHeader()->setVisible(false);
    m_tblStrings->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tblStrings->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tblStrings->setAlternatingRowColors(true);
    m_tblStrings->setStyleSheet(
        "QTableWidget { border:1px solid #ddd; border-radius:4px; font-size:12px; }"
        "QTableWidget::item { padding:4px 6px; }"
        "QTableWidget::item:selected { background:#1565c0; color:#fff; }");
    lay->addWidget(m_tblStrings, 1);
    return w;
}

QWidget *StaticScanPage::buildRulesTab()
{
    QWidget *w = new QWidget;
    QVBoxLayout *lay = new QVBoxLayout(w);
    lay->setContentsMargins(4, 4, 4, 4);
    lay->setSpacing(4);
    QLabel *hint = new QLabel("YARA 规则 / MD5 黑名单命中详情（高危行红色高亮）");
    hint->setStyleSheet("color:#666; font-size:11px; padding:2px 4px;");
    lay->addWidget(hint);

    // 规则命中查询栏
    QHBoxLayout *ruleQueryRow = new QHBoxLayout;
    ruleQueryRow->setSpacing(6);
    m_edtRuleKw = new QLineEdit;
    m_edtRuleKw->setPlaceholderText("规则名称 / 命中内容");
    m_edtRuleKw->setClearButtonEnabled(true);
    m_edtRuleKw->setFixedWidth(200);
    connect(m_edtRuleKw, &QLineEdit::returnPressed, this, &StaticScanPage::onQueryRules);
    m_cmbRuleRisk = new QComboBox;
    m_cmbRuleRisk->addItems({"全部风险", "高危(high)", "中危(medium)", "低危(low)"});
    connect(m_cmbRuleRisk, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &StaticScanPage::onQueryRules);
    QPushButton *btnRuleQuery = new QPushButton("查询");
    btnRuleQuery->setObjectName("btnPrimary");
    btnRuleQuery->setFixedWidth(70);
    connect(btnRuleQuery, &QPushButton::clicked, this, &StaticScanPage::onQueryRules);
    ruleQueryRow->addWidget(new QLabel("关键字："));
    ruleQueryRow->addWidget(m_edtRuleKw);
    ruleQueryRow->addSpacing(8);
    ruleQueryRow->addWidget(new QLabel("风险："));
    ruleQueryRow->addWidget(m_cmbRuleRisk);
    ruleQueryRow->addWidget(btnRuleQuery);
    ruleQueryRow->addStretch();
    lay->addLayout(ruleQueryRow);

    m_tblRules = new QTableWidget(0, 4);
    m_tblRules->setHorizontalHeaderLabels({"规则名称", "类型", "命中内容", "风险等级"});
    m_tblRules->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_tblRules->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_tblRules->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_tblRules->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_tblRules->verticalHeader()->setVisible(false);
    m_tblRules->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tblRules->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tblRules->setAlternatingRowColors(true);
    m_tblRules->setStyleSheet(
        "QTableWidget { border:1px solid #ddd; border-radius:4px; font-size:12px; }"
        "QTableWidget::item { padding:4px 6px; }"
        "QTableWidget::item:selected { background:#1565c0; color:#fff; }");
    lay->addWidget(m_tblRules, 1);
    return w;
}

QWidget *StaticScanPage::buildCertTab()
{
    QScrollArea *scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    QWidget *inner = new QWidget;
    QVBoxLayout *lay = new QVBoxLayout(inner);
    lay->setContentsMargins(12, 12, 12, 12);
    lay->setSpacing(12);

    // 证书查询栏
    QHBoxLayout *certQueryRow = new QHBoxLayout;
    certQueryRow->setSpacing(6);
    m_edtCertKw = new QLineEdit;
    m_edtCertKw->setPlaceholderText("文件名 / 签名者 / 题目");
    m_edtCertKw->setClearButtonEnabled(true);
    m_edtCertKw->setFixedWidth(200);
    connect(m_edtCertKw, &QLineEdit::returnPressed, this, &StaticScanPage::onQueryCert);
    m_cmbCertStatus = new QComboBox;
    m_cmbCertStatus->addItems({"全部状态", "已签名", "未签名", "证书有效", "证书过期", "文件被篹改"});
    connect(m_cmbCertStatus, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &StaticScanPage::onQueryCert);
    QPushButton *btnCertQuery = new QPushButton("查询");
    btnCertQuery->setObjectName("btnPrimary");
    btnCertQuery->setFixedWidth(70);
    connect(btnCertQuery, &QPushButton::clicked, this, &StaticScanPage::onQueryCert);
    certQueryRow->addWidget(new QLabel("关键字："));
    certQueryRow->addWidget(m_edtCertKw);
    certQueryRow->addSpacing(8);
    certQueryRow->addWidget(new QLabel("状态："));
    certQueryRow->addWidget(m_cmbCertStatus);
    certQueryRow->addWidget(btnCertQuery);
    certQueryRow->addStretch();
    lay->addLayout(certQueryRow);

    QString gbStyle =
        "QGroupBox { font-weight:bold; font-size:12px; "
        "border:1px solid #ddd; border-radius:6px; margin-top:6px; }"
        "QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; }";

    QGroupBox *statusBox = new QGroupBox("证书状态");
    statusBox->setStyleSheet(gbStyle);
    QHBoxLayout *statusRow = new QHBoxLayout(statusBox);
    statusRow->setSpacing(10);
    statusRow->setContentsMargins(12, 14, 12, 10);
    m_certStatusBadge   = makeBadge("-- 验证结论 --", "#9e9e9e");
    m_certSignedBadge   = makeBadge("签名状态", "#9e9e9e");
    m_certExpiredBadge  = makeBadge("有效期", "#9e9e9e");
    m_certTamperedBadge = makeBadge("文件完整性", "#9e9e9e");
    m_certStatusBadge->setStyleSheet(m_certStatusBadge->styleSheet()
        + "font-size:13px; padding:4px 16px;");
    statusRow->addWidget(m_certStatusBadge);
    statusRow->addSpacing(16);
    statusRow->addWidget(m_certSignedBadge);
    statusRow->addWidget(m_certExpiredBadge);
    statusRow->addWidget(m_certTamperedBadge);
    statusRow->addStretch();
    lay->addWidget(statusBox);

    QGroupBox *detailBox = new QGroupBox("证书详细信息");
    detailBox->setStyleSheet(gbStyle);
    QFormLayout *form = new QFormLayout(detailBox);
    form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    form->setHorizontalSpacing(16);
    form->setVerticalSpacing(8);
    form->setContentsMargins(12, 16, 12, 12);
    auto mkf = [](const QString &v) {
        QLabel *l = new QLabel(v);
        l->setTextInteractionFlags(Qt::TextSelectableByMouse);
        l->setStyleSheet("font-size:12px; color:#333;");
        l->setWordWrap(true);
        return l;
    };
    m_certSubject      = mkf("--");
    m_certIssuer       = mkf("--");
    m_certSerial       = mkf("--");
    m_certNotBefore    = mkf("--");
    m_certNotAfter     = mkf("--");
    m_certHashAlg      = mkf("--");
    m_certThumbprint   = mkf("--");
    m_certVerifyResult = mkf("--");
    form->addRow("签名者（Subject）：", m_certSubject);
    form->addRow("颁发机构（Issuer）：", m_certIssuer);
    form->addRow("证书序列号：",         m_certSerial);
    form->addRow("有效期起：",           m_certNotBefore);
    form->addRow("有效期止：",           m_certNotAfter);
    form->addRow("哈希算法：",           m_certHashAlg);
    form->addRow("指纹（SHA1）：",       m_certThumbprint);
    QFrame *sep = new QFrame;
    sep->setFrameShape(QFrame::HLine);
    sep->setFrameShadow(QFrame::Sunken);
    form->addRow(sep);
    form->addRow("验证结论：", m_certVerifyResult);
    lay->addWidget(detailBox);
    lay->addStretch();
    scroll->setWidget(inner);
    return scroll;
}

QWidget *StaticScanPage::buildConclusionTab()
{
    QWidget *w = new QWidget;
    QVBoxLayout *lay = new QVBoxLayout(w);
    lay->setContentsMargins(12, 12, 12, 12);
    lay->setSpacing(12);

    m_concRiskCard = new QLabel;
    m_concRiskCard->setFixedHeight(80);
    m_concRiskCard->setStyleSheet("QLabel { background:#9e9e9e; border-radius:8px; }");
    QHBoxLayout *cardRow = new QHBoxLayout(m_concRiskCard);
    cardRow->setContentsMargins(20, 0, 20, 0);
    cardRow->setSpacing(16);
    m_concRiskIcon = new QLabel("●");
    m_concRiskIcon->setStyleSheet("color:#fff; font-size:28px;");
    m_concRiskIcon->setAlignment(Qt::AlignVCenter);
    QVBoxLayout *cardText = new QVBoxLayout;
    m_concRiskText = new QLabel("等待检测");
    m_concRiskText->setStyleSheet("color:#fff; font-size:18px; font-weight:bold;");
    m_concVirusName = new QLabel("");
    m_concVirusName->setStyleSheet("color:rgba(255,255,255,0.85); font-size:12px;");
    cardText->addWidget(m_concRiskText);
    cardText->addWidget(m_concVirusName);
    cardRow->addWidget(m_concRiskIcon);
    cardRow->addLayout(cardText);
    cardRow->addStretch();
    lay->addWidget(m_concRiskCard);

    QLabel *detailHint = new QLabel("综合检测结论");
    detailHint->setStyleSheet("font-weight:bold; font-size:12px; color:#555;");
    lay->addWidget(detailHint);

    m_concText = new QTextEdit;
    m_concText->setReadOnly(true);
    m_concText->setStyleSheet(
        "QTextEdit { border:1px solid #ddd; border-radius:4px; "
        "font-size:13px; padding:8px; color:#333; background:#fafafa; }");
    m_concText->setPlaceholderText("点击左侧文件列表中的文件，查看综合检测结论...");
    lay->addWidget(m_concText, 1);
    return w;
}

void StaticScanPage::populateFileList()
{
    m_fileList->clear();
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (db.isOpen()) {
        QSqlQuery q(db);
        q.exec("SELECT id, file_name, file_path, risk_level, scan_time "
               "FROM static_scan ORDER BY id DESC LIMIT 200");
        while (q.next()) {
            int     id       = q.value(0).toInt();
            QString name     = q.value(1).toString();
            QString path     = q.value(2).toString();
            QString risk     = q.value(3).toString();
            QString scanTime = q.value(4).toString();
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
            if      (risk == "high")   item->setForeground(QColor("#c62828"));
            else if (risk == "medium") item->setForeground(QColor("#e65100"));
            else if (risk == "low")    item->setForeground(QColor("#1565c0"));
            else if (risk == "clean")  item->setForeground(QColor("#2e7d32"));
            m_fileList->addItem(item);
        }
    }
    m_lblStatus->setText(QString("文件列表：共 %1 个文件").arg(m_fileList->count()));
}

void StaticScanPage::onFileItemClicked(QListWidgetItem *item)
{
    if (!item) return;
    loadFileDetail(item->data(Qt::UserRole).toInt(),
                   item->data(Qt::UserRole + 1).toString());
}

void StaticScanPage::loadFileDetail(int staticId, const QString &filePath)
{
    clearDetail();
    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (staticId > 0 && db.isOpen()) {
        QSqlQuery q(db);
        q.prepare("SELECT file_name, file_path, file_size, file_type, md5, sha256, "
                  "       pe_info, strings_info, rule_hits, risk_level, conclusion, "
                  "       scan_time, virus_name "
                  "FROM static_scan WHERE id = ?");
        q.addBindValue(staticId);
        if (q.exec() && q.next()) {
            m_attrFileName->setText(q.value(0).toString());
            m_attrFilePath->setText(q.value(1).toString());
            qint64 sz = q.value(2).toLongLong();
            m_attrFileSize->setText(sz > 0 ?
                QString("%1 KB (%2 字节)").arg(sz/1024).arg(sz) : "--");
            m_attrFileType->setText(q.value(3).toString().isEmpty() ? "--" : q.value(3).toString());
            m_attrMd5->setText(q.value(4).toString().isEmpty() ? "--" : q.value(4).toString());
            m_attrSha256->setText(q.value(5).toString().isEmpty() ? "--" : q.value(5).toString());
            m_attrScanTime->setText(q.value(11).toString().isEmpty() ? "--" : q.value(11).toString());
            QString risk = q.value(9).toString();
            QString riskText, riskColor;
            if      (risk == "high")   { riskText = "高危"; riskColor = "#c62828"; }
            else if (risk == "medium") { riskText = "中危"; riskColor = "#e65100"; }
            else if (risk == "low")    { riskText = "低危"; riskColor = "#1565c0"; }
            else if (risk == "clean")  { riskText = "正常"; riskColor = "#2e7d32"; }
            else                       { riskText = risk;   riskColor = "#555";    }
            m_attrRiskLevel->setText(riskText);
            m_attrRiskLevel->setStyleSheet(
                QString("font-weight:bold; font-size:13px; color:%1;").arg(riskColor));
            QString virusName = q.value(12).toString();
            bool isThreat = (risk == "high" || risk == "medium");
            m_attrVirusStatus->setText(isThreat ? "威胁" : "安全");
            m_attrVirusStatus->setStyleSheet(
                isThreat ? "font-weight:bold; font-size:13px; color:#c62828;"
                         : "font-weight:bold; font-size:13px; color:#2e7d32;");
            m_attrVirusName->setText(virusName.isEmpty() ? "--" : virusName);
            m_attrVirusName->setStyleSheet(
                virusName.isEmpty() ? "color:#888;" : "color:#c62828; font-weight:bold;");
            fillPeTab(q.value(6).toString());
            fillStringsTab(q.value(7).toString());
            fillRulesTab(q.value(8).toString());
            fillConclusionTab(risk, virusName, q.value(10).toString());
        }
    } else {
        QFileInfo fi(filePath);
        m_attrFileName->setText(fi.fileName());
        m_attrFilePath->setText(filePath);
    }
    fillCertTab(filePath);
}

void StaticScanPage::fillPeTab(const QString &peInfoJson)
{
    m_treePe->clear();
    if (peInfoJson.isEmpty()) {
        new QTreeWidgetItem(m_treePe, QStringList{"提示", "PE 结构数据待检测引擎填充"});
        return;
    }
    QJsonDocument doc = QJsonDocument::fromJson(peInfoJson.toUtf8());
    if (!doc.isObject()) {
        QTreeWidgetItem *root = new QTreeWidgetItem(m_treePe, QStringList{"PE 信息", ""});
        root->setFont(0, QFont("", -1, QFont::Bold));
        for (const QString &ln : peInfoJson.split('\n', Qt::SkipEmptyParts))
            new QTreeWidgetItem(root, QStringList{"", ln.trimmed()});
        root->setExpanded(true);
        return;
    }
    QJsonObject obj = doc.object();
    if (obj.contains("header") && obj["header"].isObject()) {
        QTreeWidgetItem *hdr = new QTreeWidgetItem(m_treePe, QStringList{"PE 文件头", ""});
        hdr->setFont(0, QFont("", -1, QFont::Bold));
        hdr->setForeground(0, QColor("#1565c0"));
        QJsonObject h = obj["header"].toObject();
        for (auto it = h.begin(); it != h.end(); ++it)
            new QTreeWidgetItem(hdr, QStringList{it.key(), it.value().toVariant().toString()});
        hdr->setExpanded(true);
    }
    if (obj.contains("sections") && obj["sections"].isArray()) {
        QJsonArray secs = obj["sections"].toArray();
        QTreeWidgetItem *sn = new QTreeWidgetItem(m_treePe,
            QStringList{"节区列表", QString("共 %1 个节区").arg(secs.size())});
        sn->setFont(0, QFont("", -1, QFont::Bold));
        sn->setForeground(0, QColor("#2e7d32"));
        for (const QJsonValue &v : secs) {
            QJsonObject s = v.toObject();
            QTreeWidgetItem *si = new QTreeWidgetItem(sn, QStringList{s.value("name").toString(), ""});
            for (auto it = s.begin(); it != s.end(); ++it) {
                if (it.key() == "name") continue;
                new QTreeWidgetItem(si, QStringList{it.key(), it.value().toVariant().toString()});
            }
        }
        sn->setExpanded(true);
    }
    if (obj.contains("imports") && obj["imports"].isArray()) {
        QJsonArray imports = obj["imports"].toArray();
        QTreeWidgetItem *imp = new QTreeWidgetItem(m_treePe,
            QStringList{"导入表", QString("共 %1 个 DLL").arg(imports.size())});
        imp->setFont(0, QFont("", -1, QFont::Bold));
        imp->setForeground(0, QColor("#e65100"));
        for (const QJsonValue &v : imports) {
            QJsonObject d = v.toObject();
            QJsonArray funcs = d.value("funcs").toArray();
            QTreeWidgetItem *dn = new QTreeWidgetItem(imp,
                QStringList{d.value("dll").toString(), QString("%1 个函数").arg(funcs.size())});
            for (const QJsonValue &f : funcs)
                new QTreeWidgetItem(dn, QStringList{"", f.toString()});
        }
        imp->setExpanded(true);
    }
    if (obj.contains("exports") && obj["exports"].isArray()) {
        QJsonArray exports = obj["exports"].toArray();
        QTreeWidgetItem *exp = new QTreeWidgetItem(m_treePe,
            QStringList{"导出表", QString("共 %1 个导出").arg(exports.size())});
        exp->setFont(0, QFont("", -1, QFont::Bold));
        exp->setForeground(0, QColor("#6a1b9a"));
        for (const QJsonValue &v : exports) {
            QJsonObject e = v.toObject();
            new QTreeWidgetItem(exp, QStringList{e.value("name").toString(),
                QString("序号 %1").arg(e.value("ordinal").toInt())});
        }
        exp->setExpanded(true);
    }
}

void StaticScanPage::fillStringsTab(const QString &stringsJson)
{
    m_tblStrings->setRowCount(0);
    if (stringsJson.isEmpty()) {
        m_tblStrings->setRowCount(1);
        m_tblStrings->setItem(0, 2, new QTableWidgetItem("PE 字符串数据待检测引擎填充"));
        return;
    }
    QJsonDocument doc = QJsonDocument::fromJson(stringsJson.toUtf8());
    if (!doc.isArray()) {
        QStringList lines = stringsJson.split('\n', Qt::SkipEmptyParts);
        m_tblStrings->setRowCount(lines.size());
        for (int i = 0; i < lines.size(); i++) {
            m_tblStrings->setItem(i, 0, new QTableWidgetItem("--"));
            m_tblStrings->setItem(i, 1, new QTableWidgetItem("字符串"));
            m_tblStrings->setItem(i, 2, new QTableWidgetItem(lines[i].trimmed()));
        }
        return;
    }
    QJsonArray arr = doc.array();
    m_tblStrings->setRowCount(arr.size());
    QMap<QString,QString> tc = {
        {"URL","#c62828"},{"IP","#c62828"},{"API","#e65100"},
        {"路径","#1565c0"},{"命令","#c62828"},{"域名","#c62828"}};
    for (int i = 0; i < arr.size(); i++) {
        QJsonObject o = arr[i].toObject();
        QString offset = o.value("offset").toString();
        QString type   = o.value("type").toString();
        QString value  = o.value("value").toString();
        auto *iOff  = new QTableWidgetItem(offset);
        auto *iType = new QTableWidgetItem(type);
        auto *iVal  = new QTableWidgetItem(value);
        if (tc.contains(type)) {
            QColor c(tc[type]);
            iType->setForeground(c);
            iType->setFont(QFont("", -1, QFont::Bold));
            iVal->setForeground(c);
        }
        iOff->setFont(QFont("Monospace", -1));
        iVal->setFont(QFont("Monospace", -1));
        m_tblStrings->setItem(i, 0, iOff);
        m_tblStrings->setItem(i, 1, iType);
        m_tblStrings->setItem(i, 2, iVal);
    }
    m_tblStrings->resizeRowsToContents();
}

void StaticScanPage::fillRulesTab(const QString &rulesJson)
{
    m_tblRules->setRowCount(0);
    if (rulesJson.isEmpty()) {
        m_tblRules->setRowCount(1);
        m_tblRules->setItem(0, 2, new QTableWidgetItem("规则命中数据待检测引擎填充"));
        return;
    }
    QJsonDocument doc = QJsonDocument::fromJson(rulesJson.toUtf8());
    if (!doc.isArray()) {
        QStringList lines = rulesJson.split('\n', Qt::SkipEmptyParts);
        m_tblRules->setRowCount(lines.size());
        for (int i = 0; i < lines.size(); i++) {
            m_tblRules->setItem(i, 0, new QTableWidgetItem("规则"));
            m_tblRules->setItem(i, 1, new QTableWidgetItem("--"));
            m_tblRules->setItem(i, 2, new QTableWidgetItem(lines[i].trimmed()));
            m_tblRules->setItem(i, 3, new QTableWidgetItem("--"));
        }
        return;
    }
    QJsonArray arr = doc.array();
    m_tblRules->setRowCount(arr.size());
    for (int i = 0; i < arr.size(); i++) {
        QJsonObject o = arr[i].toObject();
        QString rule = o.value("rule").toString();
        QString type = o.value("type").toString();
        QString hit  = o.value("hit").toString();
        QString risk = o.value("risk").toString();
        QString riskText, riskColor;
        if      (risk == "high")   { riskText = "高危"; riskColor = "#c62828"; }
        else if (risk == "medium") { riskText = "中危"; riskColor = "#e65100"; }
        else if (risk == "low")    { riskText = "低危"; riskColor = "#1565c0"; }
        else                       { riskText = risk;   riskColor = "#555";    }
        auto *iRule = new QTableWidgetItem(rule);
        auto *iType = new QTableWidgetItem(type);
        auto *iHit  = new QTableWidgetItem(hit);
        auto *iRisk = new QTableWidgetItem(riskText);
        iRule->setFont(QFont("", -1, QFont::Bold));
        iRisk->setForeground(QColor(riskColor));
        iRisk->setFont(QFont("", -1, QFont::Bold));
        iRisk->setTextAlignment(Qt::AlignCenter);
        if (risk == "high") {
            QColor rowBg(255, 235, 238);
            iRule->setBackground(rowBg);
            iType->setBackground(rowBg);
            iHit->setBackground(rowBg);
            iRisk->setBackground(rowBg);
        }
        m_tblRules->setItem(i, 0, iRule);
        m_tblRules->setItem(i, 1, iType);
        m_tblRules->setItem(i, 2, iHit);
        m_tblRules->setItem(i, 3, iRisk);
    }
    m_tblRules->resizeRowsToContents();
}

void StaticScanPage::fillCertTab(const QString &filePath)
{
    auto resetBadge = [](QLabel *lbl, const QString &text) {
        lbl->setText(text);
        lbl->setStyleSheet("QLabel { background:#9e9e9e; color:#fff; "
                           "border-radius:4px; padding:2px 10px; "
                           "font-weight:bold; font-size:12px; }");
    };
    resetBadge(m_certStatusBadge,   "-- 验证结论 --");
    resetBadge(m_certSignedBadge,   "签名状态");
    resetBadge(m_certExpiredBadge,  "有效期");
    resetBadge(m_certTamperedBadge, "文件完整性");
    m_certSubject->setText("--");      m_certIssuer->setText("--");
    m_certSerial->setText("--");       m_certNotBefore->setText("--");
    m_certNotAfter->setText("--");     m_certHashAlg->setText("--");
    m_certThumbprint->setText("--");   m_certVerifyResult->setText("--");
    if (filePath.isEmpty()) return;

    QSqlDatabase db = QSqlDatabase::database("main_conn");
    if (!db.isOpen()) return;
    QSqlQuery q(db);
    q.prepare("SELECT has_signature, signature_valid, file_tampered, "
              "       subject, issuer, serial_number, not_before, not_after, "
              "       not_expired, hash_algorithm, thumbprint_sha1, verify_result "
              "FROM cert_scan WHERE file_path = ? ORDER BY id DESC LIMIT 1");
    q.addBindValue(filePath);
    if (!q.exec() || !q.next()) return;

    bool hasSig     = q.value(0).toInt() == 1;
    bool sigValid   = q.value(1).toInt() == 1;
    bool tampered   = q.value(2).toInt() == 1;
    bool notExpired = q.value(8).toInt() == 1;

    auto setBadge = [](QLabel *lbl, const QString &text,
                        const QString &bg, const QString &fg = "#fff") {
        lbl->setText(text);
        lbl->setStyleSheet(QString(
            "QLabel { background:%1; color:%2; border-radius:4px; "
            "padding:2px 10px; font-weight:bold; font-size:12px; }").arg(bg, fg));
    };
    if (!hasSig)
        setBadge(m_certStatusBadge, "无数字签名", "#c62828");
    else if (!sigValid || tampered || !notExpired)
        setBadge(m_certStatusBadge, "证书无效", "#e65100");
    else
        setBadge(m_certStatusBadge, "证书有效", "#2e7d32");
    m_certStatusBadge->setStyleSheet(m_certStatusBadge->styleSheet()
        + "font-size:13px; padding:4px 16px;");
    setBadge(m_certSignedBadge,
             hasSig ? "已签名" : "未签名", hasSig ? "#2e7d32" : "#c62828");
    if (!hasSig) setBadge(m_certExpiredBadge, "N/A", "#9e9e9e");
    else setBadge(m_certExpiredBadge,
                  notExpired ? "未过期" : "已过期", notExpired ? "#2e7d32" : "#c62828");
    setBadge(m_certTamperedBadge,
             tampered ? "文件已篡改" : "完整性正常", tampered ? "#c62828" : "#2e7d32");

    m_certSubject->setText(q.value(3).toString().isEmpty()   ? "--" : q.value(3).toString());
    m_certIssuer->setText(q.value(4).toString().isEmpty()    ? "--" : q.value(4).toString());
    m_certSerial->setText(q.value(5).toString().isEmpty()    ? "--" : q.value(5).toString());
    m_certNotBefore->setText(q.value(6).toString().isEmpty() ? "--" : q.value(6).toString());
    m_certNotAfter->setText(q.value(7).toString().isEmpty()  ? "--" : q.value(7).toString());
    m_certHashAlg->setText(q.value(9).toString().isEmpty()   ? "--" : q.value(9).toString());
    m_certThumbprint->setText(q.value(10).toString().isEmpty()? "--" : q.value(10).toString());
    QString vr = q.value(11).toString();
    m_certVerifyResult->setText(vr.isEmpty() ? "--" : vr);
    if (vr == "有效")
        m_certVerifyResult->setStyleSheet("font-size:13px; font-weight:bold; color:#2e7d32;");
    else if (!vr.isEmpty() && vr != "--")
        m_certVerifyResult->setStyleSheet("font-size:13px; font-weight:bold; color:#c62828;");
}

void StaticScanPage::fillConclusionTab(const QString &risk,
                                        const QString &virusName,
                                        const QString &conclusion)
{
    struct CfgItem { const char *bg; const char *icon; const char *text; };
    static const CfgItem cfg[] = {
        {"#c62828","⚠","高危威胁"},{"#e65100","!","中危威胁"},
        {"#1565c0","i","低危"},{"#2e7d32","✓","安全"},{"#9e9e9e","?","未知"}
    };
    int idx = 4;
    if      (risk == "high")   idx = 0;
    else if (risk == "medium") idx = 1;
    else if (risk == "low")    idx = 2;
    else if (risk == "clean")  idx = 3;
    m_concRiskCard->setStyleSheet(
        QString("QLabel { background:%1; border-radius:8px; }").arg(cfg[idx].bg));
    m_concRiskIcon->setText(cfg[idx].icon);
    m_concRiskText->setText(cfg[idx].text);
    m_concVirusName->setText(virusName.isEmpty() ? "" : "威胁名称：" + virusName);
    m_concText->setPlainText(conclusion.isEmpty()
        ? "暂无综合结论，请执行静态检测后查看。" : conclusion);
}

void StaticScanPage::clearDetail()
{
    m_attrFileName->setText("--");    m_attrFilePath->setText("--");
    m_attrFileSize->setText("--");    m_attrFileType->setText("--");
    m_attrMd5->setText("--");         m_attrSha256->setText("--");
    m_attrScanTime->setText("--");
    m_attrRiskLevel->setText("--");
    m_attrRiskLevel->setStyleSheet("font-weight:bold; font-size:13px; color:#555;");
    m_attrVirusStatus->setText("--");
    m_attrVirusStatus->setStyleSheet("font-weight:bold; font-size:13px; color:#555;");
    m_attrVirusName->setText("--");
    m_attrVirusName->setStyleSheet("color:#888;");
    m_treePe->clear();
    m_tblStrings->setRowCount(0);
    m_tblRules->setRowCount(0);
    auto rb = [](QLabel *lbl, const QString &text) {
        lbl->setText(text);
        lbl->setStyleSheet("QLabel { background:#9e9e9e; color:#fff; "
                           "border-radius:4px; padding:2px 10px; "
                           "font-weight:bold; font-size:12px; }");
    };
    rb(m_certStatusBadge,"-- 验证结论 --"); rb(m_certSignedBadge,"签名状态");
    rb(m_certExpiredBadge,"有效期");        rb(m_certTamperedBadge,"文件完整性");
    m_certSubject->setText("--");      m_certIssuer->setText("--");
    m_certSerial->setText("--");       m_certNotBefore->setText("--");
    m_certNotAfter->setText("--");     m_certHashAlg->setText("--");
    m_certThumbprint->setText("--");   m_certVerifyResult->setText("--");
    m_certVerifyResult->setStyleSheet("font-size:12px; color:#333;");
    m_concRiskCard->setStyleSheet("QLabel { background:#9e9e9e; border-radius:8px; }");
    m_concRiskIcon->setText("●");
    m_concRiskText->setText("等待检测");
    m_concVirusName->setText("");
    m_concText->clear();
}

void StaticScanPage::addFileToList(const QString &path)
{
    if (path.isEmpty()) return;
    for (int i = 0; i < m_fileList->count(); ++i)
        if (m_fileList->item(i)->data(Qt::UserRole + 1).toString() == path) return;
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

void StaticScanPage::onAddFile()
{
    QStringList paths = QFileDialog::getOpenFileNames(
        this, "选择文件", "", "所有文件 (*.*);;可执行文件 (*.exe *.dll *.sys)");
    for (const QString &p : paths) addFileToList(p);
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
            m_role, m_username, "静态检测", "提交文件：" + fi.fileName(), "success");
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
    m_lblStatus->setText(
        QString("已提交全部 %1 个文件进行检测...").arg(m_fileList->count()));
    DatabaseManager::instance()->writeLog(
        m_role, m_username, "静态检测",
        QString("批量提交 %1 个文件").arg(m_fileList->count()), "success");
}

// ─────────────────────────────────────────────────────────────────────────────
// 文件列表查询：关键字（file_name/md5）+ 风险等级 → 直接查 SQLite3
// ─────────────────────────────────────────────────────────────────────────────
void StaticScanPage::onQueryFileList()
{
    QString kw      = m_edtFileKw->text().trimmed();
    int     riskIdx = m_cmbFileRisk->currentIndex();
    // 0=全部 1=高危 2=中危 3=低危 4=安全
    static const QStringList riskMap = {"", "high", "medium", "low", "clean"};
    QString riskFilter = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";

    QString sql = "SELECT id, file_name, file_path, risk_level, scan_time "
                  "FROM static_scan WHERE 1=1";
    QVariantList binds;
    if (!kw.isEmpty()) {
        sql += " AND (file_name LIKE ? OR md5 LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like;
    }
    if (!riskFilter.isEmpty()) {
        sql += " AND risk_level = ?";
        binds << riskFilter;
    }
    sql += " ORDER BY id DESC LIMIT 200";

    m_fileList->clear();
    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int     id       = m["id"].toInt();
        QString name     = m["file_name"].toString();
        QString path     = m["file_path"].toString();
        QString risk     = m["risk_level"].toString();
        QString scanTime = m["scan_time"].toString();
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
        if      (risk == "high")   item->setForeground(QColor("#c62828"));
        else if (risk == "medium") item->setForeground(QColor("#e65100"));
        else if (risk == "low")    item->setForeground(QColor("#1565c0"));
        else if (risk == "clean")  item->setForeground(QColor("#2e7d32"));
        m_fileList->addItem(item);
    }
    m_lblStatus->setText(QString("查询结果：共 %1 个文件").arg(m_fileList->count()));
}

// ─────────────────────────────────────────────────────────────────────────────
// 字符串提取查询：对当前选中文件的 strings_info JSON 做内存过滤
// （strings_info 为 JSON blob，不单独建表，在内存中过滤）
// ─────────────────────────────────────────────────────────────────────────────
void StaticScanPage::onQueryStrings()
{
    QListWidgetItem *cur = m_fileList->currentItem();
    if (!cur) { m_lblStatus->setText("请先在左侧列表中选择文件"); return; }

    QString kw      = m_edtStrKw->text().trimmed();
    int     typeIdx = m_cmbStrType->currentIndex();
    // 0=全部 1=URL 2=IP 3=API 4=路径 5=命令 6=其他
    static const QStringList typeMap = {"", "URL", "IP", "API", "路径", "命令", "其他"};
    QString typeFilter = (typeIdx > 0 && typeIdx < typeMap.size()) ? typeMap[typeIdx] : "";

    int staticId = cur->data(Qt::UserRole).toInt();
    if (staticId <= 0) { m_lblStatus->setText("该文件尚未入库，无法查询字符串"); return; }

    // 从 DB 取 strings_info JSON
    auto rows = DatabaseManager::instance()->execSelect(
        "SELECT strings_info FROM static_scan WHERE id = ?",
        QVariantList{staticId});
    if (rows.isEmpty()) return;
    QString stringsJson = rows.first().toMap()["strings_info"].toString();

    // 解析 JSON 并在内存中过滤
    QJsonDocument doc = QJsonDocument::fromJson(stringsJson.toUtf8());
    if (!doc.isArray()) { fillStringsTab(stringsJson); return; }

    QJsonArray arr = doc.array();
    QJsonArray filtered;
    for (const QJsonValue &v : arr) {
        QJsonObject o = v.toObject();
        QString type  = o.value("type").toString();
        QString value = o.value("value").toString();
        if (!typeFilter.isEmpty() && type != typeFilter) continue;
        if (!kw.isEmpty() && !value.contains(kw, Qt::CaseInsensitive)) continue;
        filtered.append(o);
    }
    fillStringsTab(QJsonDocument(filtered).toJson(QJsonDocument::Compact));
    m_lblStatus->setText(QString("字符串查询：命中 %1 条").arg(filtered.size()));
}

// ─────────────────────────────────────────────────────────────────────────────
// 规则命中查询：对当前选中文件的 rule_hits JSON 做内存过滤
// ─────────────────────────────────────────────────────────────────────────────
void StaticScanPage::onQueryRules()
{
    QListWidgetItem *cur = m_fileList->currentItem();
    if (!cur) { m_lblStatus->setText("请先在左侧列表中选择文件"); return; }

    QString kw      = m_edtRuleKw->text().trimmed();
    int     riskIdx = m_cmbRuleRisk->currentIndex();
    // 0=全部 1=高危(high) 2=中危(medium) 3=低危(low)
    static const QStringList riskMap = {"", "high", "medium", "low"};
    QString riskFilter = (riskIdx > 0 && riskIdx < riskMap.size()) ? riskMap[riskIdx] : "";

    int staticId = cur->data(Qt::UserRole).toInt();
    if (staticId <= 0) { m_lblStatus->setText("该文件尚未入库，无法查询规则命中"); return; }

    auto rows = DatabaseManager::instance()->execSelect(
        "SELECT rule_hits FROM static_scan WHERE id = ?",
        QVariantList{staticId});
    if (rows.isEmpty()) return;
    QString rulesJson = rows.first().toMap()["rule_hits"].toString();

    QJsonDocument doc = QJsonDocument::fromJson(rulesJson.toUtf8());
    if (!doc.isArray()) { fillRulesTab(rulesJson); return; }

    QJsonArray arr = doc.array();
    QJsonArray filtered;
    for (const QJsonValue &v : arr) {
        QJsonObject o = v.toObject();
        QString rule = o.value("rule").toString();
        QString hit  = o.value("hit").toString();
        QString risk = o.value("risk").toString();
        if (!riskFilter.isEmpty() && risk != riskFilter) continue;
        if (!kw.isEmpty() &&
            !rule.contains(kw, Qt::CaseInsensitive) &&
            !hit.contains(kw, Qt::CaseInsensitive)) continue;
        filtered.append(o);
    }
    fillRulesTab(QJsonDocument(filtered).toJson(QJsonDocument::Compact));
    m_lblStatus->setText(QString("规则查询：命中 %1 条").arg(filtered.size()));
}

// ─────────────────────────────────────────────────────────────────────────────
// 数字证书查询：按关键字（file_path/subject/issuer）+ 签名状态 查 cert_scan 表
// ─────────────────────────────────────────────────────────────────────────────
void StaticScanPage::onQueryCert()
{
    QString kw         = m_edtCertKw->text().trimmed();
    int     statusIdx  = m_cmbCertStatus->currentIndex();
    // 0=全部 1=已签名 2=未签名 3=证书有效 4=证书过期 5=文件被篡改

    QString sql = "SELECT file_path, has_signature, signature_valid, file_tampered, "
                  "       subject, issuer, serial_number, not_before, not_after, "
                  "       not_expired, hash_algorithm, thumbprint_sha1, verify_result "
                  "FROM cert_scan WHERE 1=1";
    QVariantList binds;
    if (!kw.isEmpty()) {
        sql += " AND (file_path LIKE ? OR subject LIKE ? OR issuer LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like;
    }
    switch (statusIdx) {
        case 1: sql += " AND has_signature = 1";  break;  // 已签名
        case 2: sql += " AND has_signature = 0";  break;  // 未签名
        case 3: sql += " AND signature_valid = 1 AND not_expired = 1 AND file_tampered = 0"; break; // 证书有效
        case 4: sql += " AND not_expired = 0";    break;  // 证书过期
        case 5: sql += " AND file_tampered = 1";  break;  // 文件被篡改
        default: break;
    }
    sql += " ORDER BY id DESC LIMIT 100";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);

    // 证书 Tab 展示第一条匹配记录的详情
    if (!rows.isEmpty()) {
        QVariantMap m = rows.first().toMap();
        QString filePath = m["file_path"].toString();
        fillCertTab(filePath);
        m_lblStatus->setText(QString("证书查询：共 %1 条记录，显示第一条").arg(rows.size()));
    } else {
        // 清空证书详情
        auto rb = [](QLabel *lbl, const QString &text) {
            lbl->setText(text);
            lbl->setStyleSheet("QLabel { background:#9e9e9e; color:#fff; "
                               "border-radius:4px; padding:2px 10px; "
                               "font-weight:bold; font-size:12px; }");
        };
        rb(m_certStatusBadge, "无匹配记录"); rb(m_certSignedBadge, "签名状态");
        rb(m_certExpiredBadge, "有效期");    rb(m_certTamperedBadge, "文件完整性");
        m_certSubject->setText("--");        m_certIssuer->setText("--");
        m_certSerial->setText("--");         m_certNotBefore->setText("--");
        m_certNotAfter->setText("--");       m_certHashAlg->setText("--");
        m_certThumbprint->setText("--");     m_certVerifyResult->setText("--");
        m_lblStatus->setText("证书查询：无匹配记录");
    }
}
