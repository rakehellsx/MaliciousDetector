/**
 * test_pages.cpp
 * 运行时测试：直接实例化所有页面并调用 refreshData()
 * 用于检测段错误（nullptr 解引用等）
 */
#include <QApplication>
#include <QDebug>
#include <QTimer>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>

#include "DatabaseManager.h"
#include "pages/DashboardPage.h"
#include "pages/SystemInfoPage.h"
#include "pages/NetworkInfoPage.h"
#include "pages/DiskInfoPage.h"
#include "pages/ProcessInfoPage.h"
#include "pages/PortInfoPage.h"
#include "pages/AutorunPage.h"
#include "pages/ScheduledTaskPage.h"
#include "pages/DriverInfoPage.h"
#include "pages/SharedResourcePage.h"
#include "pages/BrowserPluginPage.h"
#include "pages/MemoryImagePage.h"
#include "pages/StaticScanPage.h"
#include "pages/DynamicScanPage.h"
#include "pages/FileAssocPage.h"
#include "pages/SampleExtractPage.h"
#include "pages/ReportPage.h"
#include "pages/LogAuditPage.h"
#include "pages/SystemSettingsPage.h"
#include "pages/CertScanPage.h"

static int g_pass = 0;
static int g_fail = 0;

// 信号处理：打印调用栈
void crash_handler(int sig) {
    void *array[30];
    size_t size = backtrace(array, 30);
    fprintf(stderr, "\n[CRASH] Signal %d received!\n", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    _exit(1);
}

#define TEST_PAGE(PageClass) \
    do { \
        qDebug() << "Testing" << #PageClass << "..."; \
        try { \
            PageClass *page = new PageClass(nullptr); \
            page->refreshData(); \
            delete page; \
            qDebug() << "  [PASS]" << #PageClass; \
            g_pass++; \
        } catch (const std::exception &e) { \
            qDebug() << "  [FAIL]" << #PageClass << "exception:" << e.what(); \
            g_fail++; \
        } catch (...) { \
            qDebug() << "  [FAIL]" << #PageClass << "unknown exception"; \
            g_fail++; \
        } \
    } while(0)

int main(int argc, char *argv[])
{
    // 注册崩溃信号处理
    signal(SIGSEGV, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGFPE,  crash_handler);

    QApplication app(argc, argv);
    app.setApplicationName("恶意代码辅助检测系统");
    app.setApplicationVersion("3.0.20251120");
    app.setOrganizationName("SecureDetect");

    // 初始化数据库
    if (!DatabaseManager::instance()->init()) {
        qCritical() << "[ERROR] 数据库初始化失败";
        return 1;
    }
    qDebug() << "[OK] 数据库初始化成功";

    qDebug() << "\n=== 开始逐页测试 refreshData() ===\n";

    TEST_PAGE(DashboardPage);
    TEST_PAGE(SystemInfoPage);
    TEST_PAGE(NetworkInfoPage);
    TEST_PAGE(DiskInfoPage);
    TEST_PAGE(ProcessInfoPage);
    TEST_PAGE(PortInfoPage);
    TEST_PAGE(AutorunPage);
    TEST_PAGE(ScheduledTaskPage);
    TEST_PAGE(DriverInfoPage);
    TEST_PAGE(SharedResourcePage);
    TEST_PAGE(BrowserPluginPage);
    TEST_PAGE(MemoryImagePage);
    TEST_PAGE(StaticScanPage);
    TEST_PAGE(DynamicScanPage);
    TEST_PAGE(FileAssocPage);
    TEST_PAGE(SampleExtractPage);
    TEST_PAGE(ReportPage);
    TEST_PAGE(LogAuditPage);
    TEST_PAGE(SystemSettingsPage);
    TEST_PAGE(CertScanPage);

    qDebug() << "\n=== 测试结果 ===";
    qDebug() << "通过:" << g_pass;
    qDebug() << "失败:" << g_fail;
    qDebug() << "总计:" << (g_pass + g_fail);

    DatabaseManager::instance()->close();
    return (g_fail > 0) ? 1 : 0;
}
