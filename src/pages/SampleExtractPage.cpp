#include "pages/SampleExtractPage.h"
#include "DatabaseManager.h"
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QFileInfo>
#include <QHeaderView>
#include <QLabel>
#include <QFont>
#include <QDateTime>

SampleExtractPage::SampleExtractPage(QWidget *parent)
    : BasePage("样本提取", parent)
{
    setupUi();
    refreshData();
}

void SampleExtractPage::setupUi()
{
    // ── 文件选择行 ──────────────────────────────────────────────────────────
    QHBoxLayout *fileRow = new QHBoxLayout;
    fileRow->setContentsMargins(0,0,0,8);
    m_editPath = new QLineEdit;
    m_editPath->setPlaceholderText("输入样本文件路径或拖拽文件...");
    m_editPath->setStyleSheet("QLineEdit{font-size:12px;padding:5px 8px;border:1px solid #d0d7e3;border-radius:3px;}");

    auto makeBtn = [](const QString &text, const QString &bg) -> QPushButton* {
        QPushButton *b = new QPushButton(text);
        b->setFixedWidth(90);
        b->setStyleSheet(QString("QPushButton{background:%1;color:#fff;border:none;border-radius:3px;"
                                 "padding:5px 10px;font-size:12px;}"
                                 "QPushButton:hover{opacity:0.9;}").arg(bg));
        return b;
    };
    m_btnBrowse  = makeBtn("浏览", "#595959"); m_btnBrowse->setFixedWidth(70);
    m_btnExtract = makeBtn("提取样本", "#1a3a6a");

    connect(m_btnBrowse, &QPushButton::clicked, [this](){
        QString p = QFileDialog::getOpenFileName(this, "选择文件", "", "所有文件 (*.*)");
        if (!p.isEmpty()) m_editPath->setText(p);
    });
    connect(m_btnExtract, &QPushButton::clicked, this, &SampleExtractPage::onExtract);

    fileRow->addWidget(m_editPath, 1);
    fileRow->addWidget(m_btnBrowse);
    fileRow->addWidget(m_btnExtract);
    m_mainLayout->addLayout(fileRow);

    // ── 查询栏 ──────────────────────────────────────────────────────────────
    QHBoxLayout *queryRow = new QHBoxLayout;
    queryRow->setSpacing(6);

    m_edtKeyword = new QLineEdit;
    m_edtKeyword->setPlaceholderText("文件名 / MD5 / SHA256 / 来源");
    m_edtKeyword->setClearButtonEnabled(true);
    m_edtKeyword->setFixedWidth(240);
    connect(m_edtKeyword, &QLineEdit::returnPressed, this, &SampleExtractPage::onQuery);

    m_cmbType = new QComboBox;
    m_cmbType->addItems({"全部类型", "静态", "动态"});
    connect(m_cmbType, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SampleExtractPage::onQuery);

    QPushButton *btnQuery   = new QPushButton("查询");
    btnQuery->setObjectName("btnPrimary");
    btnQuery->setFixedWidth(70);
    connect(btnQuery, &QPushButton::clicked, this, &SampleExtractPage::onQuery);

    QPushButton *btnRefresh = new QPushButton("刷新");
    btnRefresh->setObjectName("btnSecondary");
    btnRefresh->setFixedWidth(70);
    connect(btnRefresh, &QPushButton::clicked, this, &SampleExtractPage::refreshData);

    queryRow->addWidget(new QLabel("关键字："));
    queryRow->addWidget(m_edtKeyword);
    queryRow->addSpacing(8);
    queryRow->addWidget(new QLabel("来源："));
    queryRow->addWidget(m_cmbType);
    queryRow->addWidget(btnQuery);
    queryRow->addWidget(btnRefresh);
    queryRow->addStretch();
    m_mainLayout->addLayout(queryRow);

    m_lblStatus = new QLabel;
    m_lblStatus->setObjectName("statusLabel");
    m_mainLayout->addWidget(m_lblStatus);

    // DB字段: file_name, source_type, file_type, file_size, md5, sha256,
    //         original_create_time, original_modify_time, extract_time
    m_tbl = new QTableWidget(0, 9);
    m_tbl->setHorizontalHeaderLabels({
        "文件名", "来源", "文件类型", "大小",
        "MD5", "SHA256", "原始创建时间", "原始修改时间", "提取时间"
    });
    m_tbl->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_tbl->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    m_tbl->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    m_tbl->verticalHeader()->setVisible(false);
    m_tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tbl->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tbl->setAlternatingRowColors(true);
    m_tbl->setStyleSheet(
        "QTableWidget{border:1px solid #d0d7e3;font-size:12px;}"
        "QHeaderView::section{background:#e8ecf4;padding:5px 8px;font-weight:600;border:1px solid #d0d7e3;}"
        "QTableWidget::item{padding:5px 8px;}"
        "QTableWidget::item:alternate{background:#fafbfd;}");

    m_lblSummary = new QLabel;
    m_lblSummary->setStyleSheet("font-size:11px;color:#8c8c8c;padding:3px 2px;");

    m_mainLayout->addWidget(m_tbl, 1);
    m_mainLayout->addWidget(m_lblSummary);
}

void SampleExtractPage::refreshData()
{
    m_edtKeyword->clear();
    m_cmbType->setCurrentIndex(0);
    onQuery();
}

void SampleExtractPage::onQuery()
{
    QString kw      = m_edtKeyword->text().trimmed();
    int     typeIdx = m_cmbType->currentIndex();
    QStringList typeMap = {"", "静态", "动态"};
    QString typeFilter = (typeIdx > 0 && typeIdx < typeMap.size()) ? typeMap[typeIdx] : "";

    QString sql = "SELECT file_name,source_type,file_type,file_size,md5,sha256,"
                  "original_create_time,original_modify_time,extract_time "
                  "FROM sample_extract WHERE 1=1";
    QVariantList binds;

    if (!kw.isEmpty()) {
        sql += " AND (file_name LIKE ? OR md5 LIKE ? OR sha256 LIKE ? OR source_type LIKE ?)";
        QString like = "%" + kw + "%";
        binds << like << like << like << like;
    }
    if (!typeFilter.isEmpty()) {
        sql += " AND source_type = ?";
        binds << typeFilter;
    }
    sql += " ORDER BY id DESC LIMIT 200";

    auto rows = DatabaseManager::instance()->execSelect(sql, binds);
    fillTable(rows);
    m_lblStatus->setText("已刷新：" + QDateTime::currentDateTime().toString("HH:mm:ss"));
}

void SampleExtractPage::fillTable(const QVariantList &rows)
{
    m_tbl->setRowCount(0);
    for (const QVariant &v : rows) {
        QVariantMap m = v.toMap();
        int row = m_tbl->rowCount(); m_tbl->insertRow(row);
        m_tbl->setItem(row, 0, new QTableWidgetItem(m["file_name"].toString()));

        QString src = m["source_type"].toString();
        QTableWidgetItem *srcItem = new QTableWidgetItem(src);
        srcItem->setForeground(src=="动态" ? QColor("#1890ff") : QColor("#52c41a"));
        QFont sf = srcItem->font(); sf.setBold(true); srcItem->setFont(sf);
        m_tbl->setItem(row, 1, srcItem);

        m_tbl->setItem(row, 2, new QTableWidgetItem(m["file_type"].toString()));
        m_tbl->setItem(row, 3, new QTableWidgetItem(
            QString::number(m["file_size"].toLongLong()/1024) + " KB"));

        QTableWidgetItem *md5i = new QTableWidgetItem(m["md5"].toString());
        md5i->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 4, md5i);

        QTableWidgetItem *sha256i = new QTableWidgetItem(m["sha256"].toString());
        sha256i->setFont(QFont("Consolas", 11));
        m_tbl->setItem(row, 5, sha256i);

        m_tbl->setItem(row, 6, new QTableWidgetItem(m["original_create_time"].toString()));
        m_tbl->setItem(row, 7, new QTableWidgetItem(m["original_modify_time"].toString()));
        m_tbl->setItem(row, 8, new QTableWidgetItem(m["extract_time"].toString()));
    }
    m_lblSummary->setText(QString("共 %1 个样本").arg(rows.size()));
}

void SampleExtractPage::onExtract()
{
    QString path = m_editPath->text().trimmed();
    if (path.isEmpty()) { m_lblStatus->setText("请先选择文件"); return; }

    QFileInfo fi(path);
    QString sql = "INSERT INTO sample_extract(file_path,file_name,source_type,file_type,file_size,"
                  "md5,sha256,original_create_time,original_modify_time,extract_time) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?)";
    QVariantList binds;
    binds << path << fi.fileName() << "静态" << "PE32" << fi.size()
          << "（待计算）" << "（待计算）"
          << fi.birthTime().toString("yyyy-MM-dd HH:mm:ss")
          << fi.lastModified().toString("yyyy-MM-dd HH:mm:ss")
          << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");
    {
        QSqlDatabase db = QSqlDatabase::database("main_conn");
        if (db.isOpen()) {
            QSqlQuery q(db);
            q.prepare(sql);
            for (const QVariant &b : binds) q.addBindValue(b);
            q.exec();
        }
    }
    DatabaseManager::instance()->writeLog(m_role, m_username, "样本提取", fi.fileName(), "success");
    refreshData();
    m_lblStatus->setText("已提取：" + path);
}
