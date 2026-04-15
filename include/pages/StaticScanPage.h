#pragma once
#ifndef STATICSCANPAGE_H
#define STATICSCANPAGE_H

#include "pages/BasePage.h"
#include <QComboBox>
#include <QLineEdit>
#include <QListWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QTextEdit>
#include <QTabWidget>
#include <QLabel>
#include <QPushButton>
#include <QGroupBox>
#include <QSplitter>
#include <QFrame>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>

/**
 * StaticScanPage - 静态检测模块（图形化版本）
 *
 * 布局（水平 Splitter）：
 *   左侧：文件列表（QListWidget）+ 操作按钮
 *   右侧：垂直 Splitter
 *     上方：基本属性面板
 *     下方：详情 Tab（图形化）
 *       Tab1 PE 结构    → QTreeWidget 树形展示（节头/导入表/导出表/节区）
 *       Tab2 字符串提取 → QTableWidget 表格（偏移/类型/内容）
 *       Tab3 规则命中   → QTableWidget 表格（规则名/类型/命中内容/风险）
 *       Tab4 数字证书   → 卡片式表单 + 状态徽章
 *       Tab5 综合结论   → 风险评级卡片 + 结论文本
 */
namespace Ui { class StaticScanPage; }

class StaticScanPage : public BasePage {
    Q_OBJECT
public:
    explicit StaticScanPage(QWidget *parent = nullptr);
    void refreshData() override;

private slots:
    void onAddFile();
    void onRemoveFile();
    void onScanSelected();
    void onScanAll();
    void onFileItemClicked(QListWidgetItem *item);
    // 各 Tab 查询 slot
    void onQueryFileList();
    void onQueryStrings();
    void onQueryRules();
    void onQueryCert();

private:
    Ui::StaticScanPage *ui{nullptr};
    void setupUi();
    void setupAttrPanel(QWidget *parent);

    // Tab 构建函数
    QWidget *buildPeTab();
    QWidget *buildStringsTab();
    QWidget *buildRulesTab();
    QWidget *buildCertTab();
    QWidget *buildConclusionTab();

    // 数据填充函数
    void loadFileDetail(int staticId, const QString &filePath);
    void fillPeTab(const QString &peInfoJson);
    void fillStringsTab(const QString &stringsJson);
    void fillRulesTab(const QString &rulesJson);
    void fillCertTab(const QString &filePath);
    void fillConclusionTab(const QString &risk, const QString &virusName,
                           const QString &conclusion);
    void clearDetail();
    void addFileToList(const QString &path);
    void populateFileList();

    // 辅助：创建带颜色的徽章标签
    static QLabel *makeBadge(const QString &text, const QString &bg,
                              const QString &fg = "#fff", QWidget *parent = nullptr);
    // ── 左侧文件列表区 ────────────────────────────────────────────
    QListWidget  *m_fileList{nullptr};
    QPushButton  *m_btnAddFile{nullptr};
    QPushButton  *m_btnRemoveFile{nullptr};
    QPushButton  *m_btnScanSelected{nullptr};
    QPushButton  *m_btnScanAll{nullptr};
    // 文件列表查询栏
    QLineEdit    *m_edtFileKw{nullptr};
    QComboBox    *m_cmbFileRisk{nullptr};

    // ── 右侧上方：基本属性面板 ──────────────────────────────
    // 基本信息
    QLabel *m_attrFileName;
    QLabel *m_attrFilePath;
    QLabel *m_attrFileSize;
    QLabel *m_attrFileType;
    QLabel *m_attrMd5;
    QLabel *m_attrSha256;
    QLabel *m_attrScanTime;
    // 风险 & 病毒检测
    QLabel *m_attrRiskLevel;    // 高危 / 中危 / 低危 / 正常
    QLabel *m_attrVirusStatus;  // 安全 / 威胁
    QLabel *m_attrVirusName;    // 病毒名称（威胁时显示）

    // ── 右侧下方：详情 Tab ──────────────────────────────────
    QTabWidget   *m_tabDetail;

    // Tab1: PE 结构 - QTreeWidget
    QTreeWidget  *m_treePe;

    // Tab2: 字符串提取 - QTableWidget
    QLineEdit    *m_edtStrKw{nullptr};
    QComboBox    *m_cmbStrType{nullptr};
    QTableWidget *m_tblStrings{nullptr};

    // Tab3: 规则命中 - QTableWidget
    QLineEdit    *m_edtRuleKw{nullptr};
    QComboBox    *m_cmbRuleRisk{nullptr};
    QTableWidget *m_tblRules{nullptr};

    // Tab4: 数字证书 - 卡片控件
    QLineEdit    *m_edtCertKw{nullptr};
    QComboBox    *m_cmbCertStatus{nullptr};
    QLabel *m_certStatusBadge;
    QLabel *m_certSignedBadge;
    QLabel *m_certExpiredBadge;
    QLabel *m_certTamperedBadge;
    QLabel *m_certSubject;
    QLabel *m_certIssuer;
    QLabel *m_certSerial;
    QLabel *m_certNotBefore;
    QLabel *m_certNotAfter;
    QLabel *m_certHashAlg;
    QLabel *m_certThumbprint;
    QLabel *m_certVerifyResult;

    // Tab5: 综合结论 - 卡片 + 文本
    QLabel    *m_concRiskCard;
    QLabel    *m_concRiskIcon;
    QLabel    *m_concRiskText;
    QLabel    *m_concVirusName;
    QTextEdit *m_concText;
};

#endif // STATICSCANPAGE_H
