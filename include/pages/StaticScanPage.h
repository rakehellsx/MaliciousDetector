#pragma once
#ifndef STATICSCANPAGE_H
#define STATICSCANPAGE_H

#include "pages/BasePage.h"
#include <QLineEdit>
#include <QListWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QTabWidget>
#include <QLabel>
#include <QPushButton>
#include <QGroupBox>
#include <QSplitter>

/**
 * StaticScanPage - 静态检测模块
 *
 * 布局（水平 Splitter）：
 *   左侧：文件列表（QListWidget）+ 添加/删除按钮
 *   右侧：垂直 Splitter
 *     上方：基本属性面板（文件名/大小/类型/MD5/SHA256/风险等级/病毒检测）
 *     下方：详情 Tab（PE结构 | 字符串提取 | 规则命中 | 数字证书 | 综合结论）
 *
 * 数字证书检测已合并为本模块的一个 Tab，不再独立显示。
 */
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

private:
    void setupUi();
    void setupAttrPanel(QWidget *parent);
    void loadFileDetail(int staticId, const QString &filePath);
    void clearDetail();
    void addFileToList(const QString &path);
    void populateFileList();

    // ── 左侧文件列表区 ──────────────────────────────────────
    QListWidget  *m_fileList;
    QPushButton  *m_btnAddFile;
    QPushButton  *m_btnRemoveFile;
    QPushButton  *m_btnScanSelected;
    QPushButton  *m_btnScanAll;

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
    QTabWidget *m_tabDetail;
    QTextEdit  *m_txtPeInfo;
    QTextEdit  *m_txtStrings;
    QTextEdit  *m_txtRules;
    QTextEdit  *m_txtCert;      // 数字证书 Tab
    QTextEdit  *m_txtConclusion;
};

#endif // STATICSCANPAGE_H
