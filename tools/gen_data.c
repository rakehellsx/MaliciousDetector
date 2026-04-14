/*
 * gen_data.c - 恶意代码辅助检测系统数据生成及入库工具
 *
 * 依赖: cJSON (libcjson-dev), SQLite3 (libsqlite3-dev)
 *
 * 编译:
 *   gcc -O2 -o gen_data gen_data.c -lcjson -lsqlite3
 *   或使用 CMakeLists.txt: cmake .. && make
 *
 * 用法:
 *   ./gen_data -a [输出目录]      生成各模块 JSON 样例数据（默认 ./sample_data_c/）
 *   ./gen_data -p <目录>          遍历目录下 JSON 文件并写入 SQLite3
 *   ./gen_data -p <目录> --db <路径>  指定数据库路径
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include <cjson/cJSON.h>
#include <sqlite3.h>

/* ─────────────────────────────────────────────────────────────────────────── */
/* 工具宏与函数                                                                 */
/* ─────────────────────────────────────────────────────────────────────────── */

#define MAX_PATH_LEN  512
#define MAX_SQL_LEN   2048
#define RAND_INT(lo, hi) ((lo) + rand() % ((hi) - (lo) + 1))

/* 生成随机 HEX 字符串（len 个字符） */
static void rand_hex(char *buf, int len)
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < len; i++)
        buf[i] = hex[rand() % 16];
    buf[len] = '\0';
}

/* 生成 MD5 格式字符串（32位 hex） */
static void rand_md5(char *buf) { rand_hex(buf, 32); }

/* 生成 SHA1 格式字符串（40位 hex） */
static void rand_sha1(char *buf) { rand_hex(buf, 40); }

/* 生成 SHA256 格式字符串（64位 hex） */
static void rand_sha256(char *buf) { rand_hex(buf, 64); }

/* 生成随机 MAC 地址 */
static void rand_mac(char *buf)
{
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             RAND_INT(0,255), RAND_INT(0,255), RAND_INT(0,255),
             RAND_INT(0,255), RAND_INT(0,255), RAND_INT(0,255));
}

/* 生成随机 IP（192.168.x.x） */
static void rand_ip(char *buf)
{
    snprintf(buf, 20, "192.168.%d.%d", RAND_INT(1,10), RAND_INT(1,254));
}

/* 当前时间字符串，offset_min 分钟前 */
static void now_str(char *buf, int offset_min)
{
    time_t t = time(NULL) - (time_t)(offset_min * 60);
    struct tm *tm = localtime(&t);
    strftime(buf, 32, "%Y-%m-%d %H:%M:%S", tm);
}

/* 随机日期（days_back 天内） */
static void rand_date(char *buf, int days_back)
{
    time_t t = time(NULL) - (time_t)(RAND_INT(0, days_back) * 86400);
    struct tm *tm = localtime(&t);
    strftime(buf, 16, "%Y-%m-%d", tm);
}

/* 随机日期时间（days_back 天内） */
static void rand_datetime(char *buf, int days_back)
{
    time_t t = time(NULL) - (time_t)(RAND_INT(0, days_back) * 86400
                                   + RAND_INT(0, 86399));
    struct tm *tm = localtime(&t);
    strftime(buf, 32, "%Y-%m-%d %H:%M:%S", tm);
}

/* 创建目录（若不存在） */
static int mkdir_p(const char *path)
{
    char tmp[MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755);
}

/* 将 cJSON 对象写入文件 */
static int write_json_file(const char *dir, const char *filename, cJSON *root)
{
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s", dir, filename);
    char *str = cJSON_Print(root);
    if (!str) return -1;
    FILE *f = fopen(path, "w");
    if (!f) { free(str); return -1; }
    fputs(str, f);
    fclose(f);
    free(str);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* 各模块 JSON 数据生成                                                         */
/* ─────────────────────────────────────────────────────────────────────────── */

static cJSON *gen_sys_info(void)
{
    cJSON *arr = cJSON_CreateArray();
    const char *items[][2] = {
        {"操作系统",     "Windows 10 专业版 64位 (10.0.19045)"},
        {"计算机名称",   "WORKSTATION-01"},
        {"用户名",       "Administrator"},
        {"CPU型号",      "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz"},
        {"CPU核心数",    "8核16线程"},
        {"内存大小",     "16 GB"},
        {"系统盘",       "C:\\ (SSD 512GB)"},
        {"系统目录",     "C:\\Windows\\System32"},
        {"BIOS版本",     "American Megatrends Inc. F.20, 2023-06-15"},
        {"主板型号",     "ASUS PRIME Z490-A"},
        {"防火墙状态",   "已启用"},
        {"UAC状态",      "已启用"},
        {"自动更新",     "已启用"},
        {"时区",         "UTC+8 (中国标准时间)"},
        {".NET版本",     "4.8.04084"},
        {"PowerShell版本", "5.1.19041.4648"},
        {NULL, NULL}
    };
    char ts[32]; now_str(ts, RAND_INT(0, 10080));
    char sn[32]; snprintf(sn, sizeof(sn), "SN%06d", RAND_INT(100000, 999999));
    char inst[16]; rand_date(inst, 365);

    for (int i = 0; items[i][0]; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "key",   items[i][0]);
        cJSON_AddStringToObject(obj, "value", items[i][1]);
        cJSON_AddItemToArray(arr, obj);
    }
    /* 动态字段 */
    cJSON *o;
    o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "key", "启动时间");
    cJSON_AddStringToObject(o, "value", ts);
    cJSON_AddItemToArray(arr, o);

    o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "key", "系统安装日期");
    cJSON_AddStringToObject(o, "value", inst);
    cJSON_AddItemToArray(arr, o);

    o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "key", "序列号");
    cJSON_AddStringToObject(o, "value", sn);
    cJSON_AddItemToArray(arr, o);

    return arr;
}

static cJSON *gen_net_info(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct { const char *name, *ip, *mask, *gw, *status; } adapters[] = {
        {"以太网",   "192.168.1.100", "255.255.255.0", "192.168.1.1",  "已连接"},
        {"以太网 2", "10.10.0.50",    "255.255.0.0",   "10.10.0.1",    "已连接"},
        {"WLAN",     "172.16.0.88",   "255.255.255.0", "172.16.0.1",   "已断开"},
        {"Loopback", "127.0.0.1",     "255.0.0.0",     "",             "已连接"},
    };
    for (int i = 0; i < 4; i++) {
        char mac[20]; rand_mac(mac);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "name",    adapters[i].name);
        cJSON_AddStringToObject(obj, "ip",      adapters[i].ip);
        cJSON_AddStringToObject(obj, "mask",    adapters[i].mask);
        cJSON_AddStringToObject(obj, "gateway", adapters[i].gw);
        cJSON_AddStringToObject(obj, "mac",     mac);
        cJSON_AddStringToObject(obj, "status",  adapters[i].status);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_disk_info(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *drive, *type, *fs;
        double total, free, used_pct;
    } disks[] = {
        {"C:\\", "固定磁盘",   "NTFS",  512.0,  187.3, 63.4},
        {"D:\\", "固定磁盘",   "NTFS",  2048.0, 1204.7, 41.2},
        {"E:\\", "可移动磁盘", "FAT32", 64.0,   32.1,  49.8},
    };
    for (int i = 0; i < 3; i++) {
        char serial[16];
        snprintf(serial, sizeof(serial), "%s%05d",
                 i == 0 ? "SSD" : (i == 1 ? "HDD" : "USB"),
                 RAND_INT(10000, 99999));
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "drive",      disks[i].drive);
        cJSON_AddStringToObject(obj, "type",       disks[i].type);
        cJSON_AddStringToObject(obj, "filesystem", disks[i].fs);
        cJSON_AddNumberToObject(obj, "total_gb",   disks[i].total);
        cJSON_AddNumberToObject(obj, "free_gb",    disks[i].free);
        cJSON_AddNumberToObject(obj, "used_pct",   disks[i].used_pct);
        cJSON_AddStringToObject(obj, "serial",     serial);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_process_info(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *name; int pid;
        const char *user, *path;
        double cpu, mem;
        const char *status, *risk;
    } procs[] = {
        {"System",         4,    "NT AUTHORITY\\SYSTEM",  "C:\\Windows\\System32\\ntoskrnl.exe",                                          0.1,   2.4,  "运行中", "clean"},
        {"svchost.exe",    1234, "NT AUTHORITY\\SYSTEM",  "C:\\Windows\\System32\\svchost.exe",                                           0.3,  18.2,  "运行中", "clean"},
        {"explorer.exe",   3456, "WORKSTATION-01\\Admin", "C:\\Windows\\explorer.exe",                                                    1.2,  52.6,  "运行中", "clean"},
        {"chrome.exe",     5678, "WORKSTATION-01\\Admin", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",                   3.5, 312.4,  "运行中", "clean"},
        {"python3.exe",    7890, "WORKSTATION-01\\Admin", "C:\\Python39\\python3.exe",                                                    0.8,  24.1,  "运行中", "clean"},
        {"svchost32.exe",  9012, "NT AUTHORITY\\SYSTEM",  "C:\\Windows\\Temp\\svchost32.exe",                                             8.7,  64.3,  "运行中", "高危"},
        {"update.exe",     1111, "WORKSTATION-01\\Admin", "C:\\Users\\Admin\\AppData\\Roaming\\update.exe",                               2.1,  12.8,  "运行中", "中危"},
        {"lsass.exe",       888, "NT AUTHORITY\\SYSTEM",  "C:\\Windows\\System32\\lsass.exe",                                             0.2,   8.6,  "运行中", "clean"},
        {"winlogon.exe",    600, "NT AUTHORITY\\SYSTEM",  "C:\\Windows\\System32\\winlogon.exe",                                          0.1,   4.2,  "运行中", "clean"},
        {"taskmgr.exe",    4321, "WORKSTATION-01\\Admin", "C:\\Windows\\System32\\taskmgr.exe",                                           0.5,  16.3,  "运行中", "clean"},
        {"notepad.exe",    6543, "WORKSTATION-01\\Admin", "C:\\Windows\\System32\\notepad.exe",                                           0.0,   4.1,  "运行中", "clean"},
        {"cmd.exe",        7654, "WORKSTATION-01\\Admin", "C:\\Windows\\System32\\cmd.exe",                                               0.0,   2.3,  "运行中", "clean"},
        {"powershell.exe", 8765, "WORKSTATION-01\\Admin", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",               1.1,  38.2,  "运行中", "中危"},
        {"wscript.exe",    2233, "WORKSTATION-01\\Admin", "C:\\Windows\\System32\\wscript.exe",                                           0.3,   6.7,  "运行中", "中危"},
        {"spoolsv.exe",    1560, "NT AUTHORITY\\SYSTEM",  "C:\\Windows\\System32\\spoolsv.exe",                                           0.1,  10.2,  "运行中", "clean"},
    };
    for (int i = 0; i < 15; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "pid",     procs[i].pid);
        cJSON_AddStringToObject(obj, "name",    procs[i].name);
        cJSON_AddStringToObject(obj, "path",    procs[i].path);
        cJSON_AddStringToObject(obj, "user",    procs[i].user);
        cJSON_AddNumberToObject(obj, "cpu_pct", procs[i].cpu);
        cJSON_AddNumberToObject(obj, "mem_mb",  procs[i].mem);
        cJSON_AddStringToObject(obj, "status",  procs[i].status);
        cJSON_AddStringToObject(obj, "risk",    procs[i].risk);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_port_info(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *proto, *lip, *rip, *state, *proc, *risk;
        int lport, rport, pid;
    } ports[] = {
        {"TCP", "0.0.0.0",       "",              "LISTEN",      "nginx.exe",      "clean", 80,    0,    1234},
        {"TCP", "0.0.0.0",       "",              "LISTEN",      "nginx.exe",      "clean", 443,   0,    1234},
        {"TCP", "0.0.0.0",       "",              "LISTEN",      "svchost.exe",    "中危",  3389,  0,    888},
        {"TCP", "192.168.1.100", "192.168.1.200", "ESTABLISHED", "System",         "clean", 49152, 445,  4},
        {"TCP", "192.168.1.100", "8.8.8.8",       "ESTABLISHED", "chrome.exe",     "clean", 49200, 53,   5678},
        {"TCP", "0.0.0.0",       "",              "LISTEN",      "svchost32.exe",  "高危",  4444,  0,    9012},
        {"UDP", "0.0.0.0",       "",              "LISTEN",      "svchost.exe",    "clean", 5353,  0,    1234},
        {"TCP", "127.0.0.1",     "",              "LISTEN",      "python3.exe",    "clean", 8080,  0,    7890},
        {"TCP", "192.168.1.100", "10.10.0.1",     "ESTABLISHED", "putty.exe",      "clean", 49300, 22,   3456},
        {"UDP", "0.0.0.0",       "",              "LISTEN",      "System",         "clean", 137,   0,    4},
        {"TCP", "0.0.0.0",       "",              "LISTEN",      "sqlservr.exe",   "中危",  1433,  0,    2345},
        {"TCP", "192.168.1.100", "185.220.101.1", "ESTABLISHED", "update.exe",     "高危",  49400, 1080, 1111},
    };
    for (int i = 0; i < 12; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "protocol",     ports[i].proto);
        cJSON_AddStringToObject(obj, "local_ip",     ports[i].lip);
        cJSON_AddNumberToObject(obj, "local_port",   ports[i].lport);
        cJSON_AddStringToObject(obj, "remote_ip",    ports[i].rip);
        cJSON_AddNumberToObject(obj, "remote_port",  ports[i].rport);
        cJSON_AddStringToObject(obj, "state",        ports[i].state);
        cJSON_AddStringToObject(obj, "process_name", ports[i].proc);
        cJSON_AddNumberToObject(obj, "pid",          ports[i].pid);
        cJSON_AddStringToObject(obj, "risk",         ports[i].risk);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_autorun_info(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *type, *name, *reg_path, *value, *cmd, *publisher, *risk;
    } items[] = {
        {"reg",     "SecurityHealth",
         "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "SecurityHealth", "C:\\Windows\\System32\\SecurityHealthSystray.exe",
         "Microsoft Corporation", "正常"},
        {"reg",     "OneDrive",
         "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "OneDrive", "C:\\Users\\Admin\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background",
         "Microsoft Corporation", "正常"},
        {"reg",     "Updater",
         "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "Updater", "C:\\Users\\Admin\\AppData\\Roaming\\update.exe --silent",
         "Unknown", "高危"},
        {"reg",     "SvcHelper",
         "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
         "SvcHelper", "C:\\Windows\\Temp\\svchost32.exe -k netsvcs",
         "", "高危"},
        {"folder",  "TeamViewer.lnk",
         "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
         "", "C:\\Program Files\\TeamViewer\\TeamViewer.exe",
         "TeamViewer GmbH", "正常"},
        {"folder",  "malware.lnk",
         "C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
         "", "C:\\Users\\Admin\\AppData\\Local\\Temp\\malware.exe",
         "", "高危"},
        {"menu",    "7-Zip",
         "HKCR\\*\\shellex\\ContextMenuHandlers\\7-Zip",
         "", "C:\\Program Files\\7-Zip\\7-zip.dll",
         "Igor Pavlov", "正常"},
        {"menu",    "ShellExt",
         "HKCR\\*\\shellex\\ContextMenuHandlers\\ShellExt",
         "", "C:\\Windows\\Temp\\shellext.dll",
         "", "中危"},
        {"debugger","notepad.exe",
         "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe",
         "Debugger", "C:\\Windows\\Temp\\svchost32.exe",
         "", "高危"},
    };
    for (int i = 0; i < 9; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "type",      items[i].type);
        cJSON_AddStringToObject(obj, "name",      items[i].name);
        cJSON_AddStringToObject(obj, "reg_path",  items[i].reg_path);
        cJSON_AddStringToObject(obj, "value",     items[i].value);
        cJSON_AddStringToObject(obj, "cmd",       items[i].cmd);
        cJSON_AddStringToObject(obj, "publisher", items[i].publisher);
        cJSON_AddStringToObject(obj, "risk",      items[i].risk);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_scheduled_task(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *name, *path, *trigger, *action, *status, *risk;
        int last_run_days;
    } tasks[] = {
        {"MicrosoftEdgeUpdateTaskMachineCore",
         "\\Microsoft\\EdgeUpdate\\", "每天 09:00",
         "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe /c",
         "就绪", "正常", 3},
        {"WindowsDefenderScheduledScan",
         "\\Microsoft\\Windows Defender\\", "每周日 02:00",
         "C:\\Program Files\\Windows Defender\\MpCmdRun.exe -Scan -ScanType 2",
         "就绪", "正常", 7},
        {"GoogleUpdateTaskMachineCore",
         "\\GoogleUpdate\\", "每天 08:00",
         "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c",
         "就绪", "正常", 1},
        {"SysMonitor",
         "\\Custom\\", "系统启动时",
         "C:\\Windows\\Temp\\svchost32.exe --monitor",
         "运行中", "高危", 0},
        {"BackupTask",
         "\\Custom\\", "每天 23:00",
         "C:\\Users\\Admin\\AppData\\Roaming\\backup.bat",
         "就绪", "中危", 1},
        {"WindowsUpdateCheck",
         "\\Microsoft\\Windows\\UpdateOrchestrator\\", "每天 03:00",
         "C:\\Windows\\System32\\UsoClient.exe StartScan",
         "就绪", "正常", 2},
    };
    for (int i = 0; i < 6; i++) {
        char last_run[32]; rand_datetime(last_run, tasks[i].last_run_days + 1);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "name",     tasks[i].name);
        cJSON_AddStringToObject(obj, "path",     tasks[i].path);
        cJSON_AddStringToObject(obj, "trigger",  tasks[i].trigger);
        cJSON_AddStringToObject(obj, "action",   tasks[i].action);
        cJSON_AddStringToObject(obj, "status",   tasks[i].status);
        cJSON_AddStringToObject(obj, "last_run", last_run);
        cJSON_AddStringToObject(obj, "risk",     tasks[i].risk);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_driver_info(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *name, *type, *publisher, *path, *risk;
        int is_signed, days;
    } drivers[] = {
        {"ntfs.sys",            "内核驱动", "Microsoft Corporation",
         "C:\\Windows\\System32\\drivers\\ntfs.sys",           "正常", 1, 180},
        {"tcpip.sys",           "内核驱动", "Microsoft Corporation",
         "C:\\Windows\\System32\\drivers\\tcpip.sys",          "正常", 1, 180},
        {"ndis.sys",            "内核驱动", "Microsoft Corporation",
         "C:\\Windows\\System32\\drivers\\ndis.sys",           "正常", 1, 180},
        {"nvlddmkm.sys",        "设备驱动", "NVIDIA Corporation",
         "C:\\Windows\\System32\\drivers\\nvlddmkm.sys",       "正常", 1, 90},
        {"360AntiHacker64.sys", "第三方",   "360 Software",
         "C:\\Program Files\\360\\360Safe\\deepscan\\360AntiHacker64.sys", "正常", 1, 30},
        {"rootkit.sys",         "内核驱动", "",
         "C:\\Windows\\Temp\\rootkit.sys",                     "高危", 0, 7},
        {"hookdrv.sys",         "第三方",   "Unknown",
         "C:\\Windows\\System32\\drivers\\hookdrv.sys",        "中危", 0, 14},
        {"WdFilter.sys",        "内核驱动", "Microsoft Corporation",
         "C:\\Windows\\System32\\drivers\\wd\\WdFilter.sys",   "正常", 1, 60},
    };
    for (int i = 0; i < 8; i++) {
        char mtime[16]; rand_date(mtime, drivers[i].days);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "name",          drivers[i].name);
        cJSON_AddStringToObject(obj, "type",          drivers[i].type);
        cJSON_AddStringToObject(obj, "publisher",     drivers[i].publisher);
        cJSON_AddStringToObject(obj, "modified_time", mtime);
        cJSON_AddStringToObject(obj, "path",          drivers[i].path);
        cJSON_AddNumberToObject(obj, "is_signed",     drivers[i].is_signed);
        cJSON_AddStringToObject(obj, "risk",          drivers[i].risk);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_shared_resource(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *name, *path, *type, *permission, *risk;
        int connected;
    } shares[] = {
        {"ADMIN$", "C:\\Windows",       "系统共享", "完全控制", "正常", 0},
        {"C$",     "C:\\",              "系统共享", "完全控制", "中危", 1},
        {"IPC$",   "",                  "IPC共享",  "读取",     "正常", 0},
        {"Share",  "D:\\Share",         "用户共享", "读写",     "正常", 2},
        {"Backup", "D:\\Backup",        "用户共享", "完全控制", "正常", 0},
        {"Temp",   "C:\\Windows\\Temp", "用户共享", "完全控制", "高危", 3},
    };
    for (int i = 0; i < 6; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "name",       shares[i].name);
        cJSON_AddStringToObject(obj, "path",       shares[i].path);
        cJSON_AddStringToObject(obj, "type",       shares[i].type);
        cJSON_AddStringToObject(obj, "permission", shares[i].permission);
        cJSON_AddNumberToObject(obj, "connected",  shares[i].connected);
        cJSON_AddStringToObject(obj, "risk",       shares[i].risk);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_browser_plugin(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *browser, *name, *version, *publisher, *status, *risk;
    } plugins[] = {
        {"Chrome",  "Google Docs Offline", "1.65.0",  "Google LLC",           "已启用", "正常"},
        {"Chrome",  "AdBlock",             "5.18.0",  "AdBlock",              "已启用", "正常"},
        {"Chrome",  "Unknown Extension",   "0.1.0",   "Unknown",              "已启用", "高危"},
        {"Edge",    "Microsoft Editor",    "3.0.14",  "Microsoft Corporation","已启用", "正常"},
        {"Edge",    "Shopping Helper",     "2.3.1",   "Unknown",              "已禁用", "中危"},
        {"Firefox", "uBlock Origin",       "1.56.0",  "Raymond Hill",         "已启用", "正常"},
        {"Firefox", "Tampermonkey",        "5.0.0",   "Jan Biniok",           "已启用", "正常"},
        {"IE",      "Adobe Flash Player",  "32.0.0",  "Adobe Inc.",           "已禁用", "中危"},
    };
    for (int i = 0; i < 8; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "browser",   plugins[i].browser);
        cJSON_AddStringToObject(obj, "name",      plugins[i].name);
        cJSON_AddStringToObject(obj, "version",   plugins[i].version);
        cJSON_AddStringToObject(obj, "publisher", plugins[i].publisher);
        cJSON_AddStringToObject(obj, "status",    plugins[i].status);
        cJSON_AddStringToObject(obj, "risk",      plugins[i].risk);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_memory_status(void)
{
    cJSON *arr = cJSON_CreateArray();
    int total = 16384;
    int used  = RAND_INT(6000, 12000);
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "total_mb",   total);
    cJSON_AddNumberToObject(obj, "used_mb",    used);
    cJSON_AddNumberToObject(obj, "avail_mb",   total - used);
    cJSON_AddNumberToObject(obj, "virtual_mb", 32768);
    cJSON_AddStringToObject(obj, "page_file",  "C:\\pagefile.sys (4096MB)");
    cJSON_AddItemToArray(arr, obj);
    return arr;
}

static cJSON *gen_kernel_module(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *name, *base, *size, *flags, *path;
        int trusted;
    } mods[] = {
        {"ntoskrnl.exe", "0xFFFFF80000000000", "0x00A00000", "LDRP_ENTRY_PROCESSED",
         "C:\\Windows\\System32\\ntoskrnl.exe", 1},
        {"hal.dll",      "0xFFFFF80000B00000", "0x00080000", "LDRP_ENTRY_PROCESSED",
         "C:\\Windows\\System32\\hal.dll", 1},
        {"ntfs.sys",     "0xFFFFF88000100000", "0x00200000", "LDRP_ENTRY_PROCESSED",
         "C:\\Windows\\System32\\drivers\\ntfs.sys", 1},
        {"tcpip.sys",    "0xFFFFF88001000000", "0x00300000", "LDRP_ENTRY_PROCESSED",
         "C:\\Windows\\System32\\drivers\\tcpip.sys", 1},
        {"ndis.sys",     "0xFFFFF88001400000", "0x00180000", "LDRP_ENTRY_PROCESSED",
         "C:\\Windows\\System32\\drivers\\ndis.sys", 1},
        {"rootkit.sys",  "0xFFFFF88002000000", "0x00010000", "LDRP_ENTRY_PROCESSED",
         "C:\\Windows\\Temp\\rootkit.sys", 0},
        {"WdFilter.sys", "0xFFFFF88003000000", "0x00100000", "LDRP_ENTRY_PROCESSED",
         "C:\\Windows\\System32\\drivers\\wd\\WdFilter.sys", 1},
    };
    for (int i = 0; i < 7; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "name",         mods[i].name);
        cJSON_AddStringToObject(obj, "base_address", mods[i].base);
        cJSON_AddStringToObject(obj, "image_size",   mods[i].size);
        cJSON_AddStringToObject(obj, "flags",        mods[i].flags);
        cJSON_AddNumberToObject(obj, "idx",          i + 1);
        cJSON_AddStringToObject(obj, "path",         mods[i].path);
        cJSON_AddNumberToObject(obj, "is_trusted",   mods[i].trusted);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_process_memory(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *name; int pid, priv, ws, virt, inject;
    } procs[] = {
        {"System",         4,    2,   8,    16,   0},
        {"svchost.exe",    1234, 18,  42,   128,  0},
        {"explorer.exe",   3456, 52,  120,  512,  0},
        {"chrome.exe",     5678, 312, 480,  2048, 0},
        {"svchost32.exe",  9012, 64,  128,  256,  1},
        {"lsass.exe",      888,  8,   24,   64,   0},
        {"update.exe",     1111, 12,  28,   96,   1},
        {"powershell.exe", 8765, 38,  64,   256,  0},
    };
    for (int i = 0; i < 8; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "name",              procs[i].name);
        cJSON_AddNumberToObject(obj, "pid",               procs[i].pid);
        cJSON_AddNumberToObject(obj, "private_mb",        procs[i].priv);
        cJSON_AddNumberToObject(obj, "working_set_mb",    procs[i].ws);
        cJSON_AddNumberToObject(obj, "virtual_mb",        procs[i].virt);
        cJSON_AddNumberToObject(obj, "suspicious_inject", procs[i].inject);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_static_scan(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *fp, *fn, *ft, *pub, *risk, *vname, *conc;
        int fsize;
    } files[] = {
        {"C:\\Windows\\Temp\\svchost32.exe", "svchost32.exe", "PE32",
         "Unknown", "high", "Trojan.Generic.12345",
         "PE结构异常，存在加壳特征，导入表包含可疑API", 245760},
        {"C:\\Users\\Admin\\AppData\\Roaming\\update.exe", "update.exe", "PE32",
         "Unknown", "medium", "Adware.Generic",
         "无数字签名，存在可疑网络连接行为", 102400},
        {"C:\\Windows\\System32\\notepad.exe", "notepad.exe", "PE32+",
         "Microsoft Corporation", "clean", "",
         "系统文件，数字签名有效，未发现威胁", 204800},
        {"C:\\Users\\Admin\\Desktop\\readme.pdf.exe", "readme.pdf.exe", "PE32",
         "", "high", "Ransomware.WannaCry.Variant",
         "双扩展名欺骗，无签名，包含加密勒索特征", 51200},
        {"C:\\Program Files\\7-Zip\\7z.exe", "7z.exe", "PE32+",
         "Igor Pavlov", "clean", "",
         "已知安全软件，数字签名有效", 1048576},
    };
    for (int i = 0; i < 5; i++) {
        char md5[33], sha1[41], sha256[65], ct[32], st[32];
        rand_md5(md5); rand_sha1(sha1); rand_sha256(sha256);
        rand_datetime(ct, 365); rand_datetime(st, 7);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "file_path",    files[i].fp);
        cJSON_AddStringToObject(obj, "file_name",    files[i].fn);
        cJSON_AddNumberToObject(obj, "file_size",    files[i].fsize);
        cJSON_AddStringToObject(obj, "file_type",    files[i].ft);
        cJSON_AddStringToObject(obj, "md5",          md5);
        cJSON_AddStringToObject(obj, "sha1",         sha1);
        cJSON_AddStringToObject(obj, "sha256",       sha256);
        cJSON_AddStringToObject(obj, "compile_time", ct);
        cJSON_AddStringToObject(obj, "publisher",    files[i].pub);
        cJSON_AddStringToObject(obj, "pe_info",      "[]");
        cJSON_AddStringToObject(obj, "strings_info", "");
        cJSON_AddStringToObject(obj, "rule_hits",    "[]");
        cJSON_AddStringToObject(obj, "risk_level",   files[i].risk);
        cJSON_AddStringToObject(obj, "virus_name",   files[i].vname);
        cJSON_AddStringToObject(obj, "conclusion",   files[i].conc);
        cJSON_AddStringToObject(obj, "scan_time",    st);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_cert_scan(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *fp, *subject, *issuer, *not_before, *not_after, *verify;
        int has_sig, sig_valid, tampered, not_expired;
    } certs[] = {
        {"C:\\Windows\\System32\\notepad.exe",
         "Microsoft Corporation", "Microsoft Root CA",
         "2023-04-11 09:00:00", "2025-04-11 09:00:00", "有效",
         1, 1, 0, 1},
        {"C:\\Windows\\Temp\\svchost32.exe",
         "", "", "", "", "无签名",
         0, 0, 0, 0},
        {"C:\\Users\\Admin\\Desktop\\readme.pdf.exe",
         "", "", "", "", "无签名",
         0, 0, 0, 0},
        {"C:\\Users\\Admin\\AppData\\Roaming\\update.exe",
         "Unknown Publisher", "Unknown CA",
         "2022-01-01 00:00:00", "2023-01-01 00:00:00", "证书过期",
         1, 0, 1, 0},
        {"C:\\Program Files\\7-Zip\\7z.exe",
         "Igor Pavlov", "Sectigo RSA Code Signing CA",
         "2024-06-01 00:00:00", "2026-06-01 00:00:00", "有效",
         1, 1, 0, 1},
    };
    for (int i = 0; i < 5; i++) {
        char sha1[41], sha256[65];
        rand_sha1(sha1); rand_sha256(sha256);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "file_path",         certs[i].fp);
        cJSON_AddNumberToObject(obj, "has_signature",     certs[i].has_sig);
        cJSON_AddNumberToObject(obj, "signature_valid",   certs[i].sig_valid);
        cJSON_AddNumberToObject(obj, "file_tampered",     certs[i].tampered);
        cJSON_AddStringToObject(obj, "subject",           certs[i].subject);
        cJSON_AddStringToObject(obj, "issuer",            certs[i].issuer);
        cJSON_AddStringToObject(obj, "serial_number",     "3300000266");
        cJSON_AddStringToObject(obj, "not_before",        certs[i].not_before);
        cJSON_AddStringToObject(obj, "not_after",         certs[i].not_after);
        cJSON_AddNumberToObject(obj, "not_expired",       certs[i].not_expired);
        cJSON_AddStringToObject(obj, "hash_algorithm",    certs[i].has_sig ? "SHA256" : "");
        cJSON_AddStringToObject(obj, "thumbprint_sha1",   sha1);
        cJSON_AddStringToObject(obj, "thumbprint_sha256", sha256);
        cJSON_AddStringToObject(obj, "verify_result",     certs[i].verify);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_dynamic_scan(void)
{
    cJSON *arr = cJSON_CreateArray();
    const char *sample = "C:\\Windows\\Temp\\svchost32.exe";
    struct {
        const char *btype, *atype, *src, *target, *detail, *risk;
        int ppid, pid;
    } behaviors[] = {
        {"registry", "SetValue",  "svchost32.exe",
         "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcHelper",
         "写入启动项", "high", 0, 9012},
        {"registry", "CreateKey", "svchost32.exe",
         "HKLM\\SYSTEM\\CurrentControlSet\\Services\\maldrv",
         "创建服务注册表项", "high", 0, 9012},
        {"file",     "Write",     "svchost32.exe",
         "C:\\Windows\\System32\\drivers\\maldrv.sys",
         "写入驱动文件", "high", 0, 9012},
        {"file",     "Create",    "svchost32.exe",
         "C:\\Users\\Admin\\AppData\\Roaming\\config.dat",
         "创建配置文件", "medium", 0, 9012},
        {"process",  "Inject",    "svchost32.exe",
         "lsass.exe", "进程注入 lsass.exe", "high", 9012, 888},
        {"process",  "Create",    "svchost32.exe",
         "cmd.exe",   "创建子进程 cmd.exe", "medium", 9012, 7654},
        {"network",  "Connect",   "svchost32.exe",
         "185.220.101.1:4444", "连接 C2 服务器", "high", 0, 9012},
        {"network",  "DNS",       "svchost32.exe",
         "evil-c2.example.com", "DNS 查询可疑域名", "high", 0, 9012},
    };
    for (int i = 0; i < 8; i++) {
        char st[32]; rand_datetime(st, 1);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "sample_path",   sample);
        cJSON_AddStringToObject(obj, "behavior_type", behaviors[i].btype);
        cJSON_AddStringToObject(obj, "action_type",   behaviors[i].atype);
        cJSON_AddStringToObject(obj, "source_proc",   behaviors[i].src);
        cJSON_AddStringToObject(obj, "target_path",   behaviors[i].target);
        cJSON_AddStringToObject(obj, "detail",        behaviors[i].detail);
        cJSON_AddStringToObject(obj, "risk_level",    behaviors[i].risk);
        cJSON_AddNumberToObject(obj, "parent_pid",    behaviors[i].ppid);
        cJSON_AddNumberToObject(obj, "pid",           behaviors[i].pid);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_file_assoc_scan(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *ext, *assoc_type, *orig, *curr, *risk;
    } assocs[] = {
        {".exe", "正常",
         "\"C:\\Windows\\System32\\cmd.exe\" \"%1\" %*",
         "\"C:\\Windows\\System32\\cmd.exe\" \"%1\" %*", "clean"},
        {".bat", "正常",
         "C:\\Windows\\System32\\cmd.exe /c \"%1\" %*",
         "C:\\Windows\\System32\\cmd.exe /c \"%1\" %*", "clean"},
        {".txt", "篡改",
         "C:\\Windows\\System32\\notepad.exe %1",
         "C:\\Windows\\Temp\\svchost32.exe --open %1", "high"},
        {".pdf", "篡改",
         "\"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe\" \"%1\"",
         "C:\\Users\\Admin\\AppData\\Roaming\\update.exe --pdf \"%1\"", "high"},
        {".html", "正常",
         "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" -- \"%1\"",
         "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" -- \"%1\"", "clean"},
        {".docx", "正常",
         "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"%1\"",
         "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"%1\"", "clean"},
    };
    for (int i = 0; i < 6; i++) {
        char st[32]; rand_datetime(st, 7);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "ext",          assocs[i].ext);
        cJSON_AddStringToObject(obj, "assoc_type",   assocs[i].assoc_type);
        cJSON_AddStringToObject(obj, "original_cmd", assocs[i].orig);
        cJSON_AddStringToObject(obj, "current_cmd",  assocs[i].curr);
        cJSON_AddStringToObject(obj, "risk_level",   assocs[i].risk);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_sample_extract(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct {
        const char *src, *etype, *dst, *note;
    } samples[] = {
        {"C:\\Windows\\Temp\\svchost32.exe",
         "可执行文件", "D:\\Samples\\svchost32_20251101.exe",
         "高危样本，疑似远控木马"},
        {"C:\\Users\\Admin\\Desktop\\readme.pdf.exe",
         "可执行文件", "D:\\Samples\\readme.pdf.exe_20251101.exe",
         "双扩展名欺骗，疑似勒索软件"},
        {"C:\\Users\\Admin\\AppData\\Roaming\\update.exe",
         "可执行文件", "D:\\Samples\\update_20251101.exe",
         "广告软件"},
    };
    for (int i = 0; i < 3; i++) {
        char md5[33], sha256[65], mtime[32], ctime[32];
        rand_md5(md5); rand_sha256(sha256);
        rand_datetime(mtime, 7); rand_datetime(ctime, 30);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "source_path",    samples[i].src);
        cJSON_AddStringToObject(obj, "extract_type",   samples[i].etype);
        cJSON_AddStringToObject(obj, "sample_path",    samples[i].dst);
        cJSON_AddStringToObject(obj, "md5",            md5);
        cJSON_AddStringToObject(obj, "sha256",         sha256);
        cJSON_AddStringToObject(obj, "original_mtime", mtime);
        cJSON_AddStringToObject(obj, "original_ctime", ctime);
        cJSON_AddStringToObject(obj, "note",           samples[i].note);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_audit_log(void)
{
    cJSON *arr = cJSON_CreateArray();
    const char *users[][2] = {
        {"admin",    "system_admin"},
        {"secadmin", "sec_admin"},
        {"auditor",  "auditor"},
    };
    struct { const char *action, *detail, *result; } actions[] = {
        {"登录",   "用户登录系统",       "success"},
        {"扫描",   "执行静态检测扫描",   "success"},
        {"导出",   "导出检测报告",       "success"},
        {"设置",   "修改扫描策略配置",   "success"},
        {"白名单", "添加白名单条目",     "success"},
        {"登出",   "用户登出系统",       "success"},
        {"登录",   "用户登录失败",       "fail"},
        {"规则",   "新增自定义规则",     "success"},
    };
    for (int i = 0; i < 20; i++) {
        int ui = RAND_INT(0, 2);
        int ai = RAND_INT(0, 7);
        char ip[20], ts[32];
        rand_ip(ip); rand_datetime(ts, 30);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "role",       users[ui][1]);
        cJSON_AddStringToObject(obj, "username",   users[ui][0]);
        cJSON_AddStringToObject(obj, "action",     actions[ai].action);
        cJSON_AddStringToObject(obj, "detail",     actions[ai].detail);
        cJSON_AddStringToObject(obj, "result",     actions[ai].result);
        cJSON_AddStringToObject(obj, "ip_address", ip);
        cJSON_AddStringToObject(obj, "timestamp",  ts);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_whitelist(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct { const char *path, *note, *added_by; } items[] = {
        {"C:\\Windows\\System32\\notepad.exe", "系统文件",     "admin"},
        {"C:\\Program Files\\7-Zip\\7z.exe",  "已知安全软件", "secadmin"},
        {"",                                   "MD5白名单",    "admin"},
    };
    for (int i = 0; i < 3; i++) {
        char md5[33]; rand_md5(md5);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "path",     items[i].path);
        cJSON_AddStringToObject(obj, "md5",      md5);
        cJSON_AddStringToObject(obj, "note",     items[i].note);
        cJSON_AddStringToObject(obj, "added_by", items[i].added_by);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

static cJSON *gen_custom_rules(void)
{
    cJSON *arr = cJSON_CreateArray();
    struct { const char *name, *rtype, *pattern, *desc; } rules[] = {
        {"YARA_RULE_001", "YARA",
         "rule TrojanGeneric { strings: $a = \"CreateRemoteThread\" condition: $a }",
         "疑似远控木马特征"},
        {"YARA_RULE_002", "YARA",
         "rule ProcessInjection { strings: $a = \"VirtualAllocEx\" $b = \"WriteProcessMemory\" condition: $a and $b }",
         "进程注入特征"},
        {"YARA_RULE_003", "YARA",
         "rule Adware { strings: $a = \"WinInet\" $b = \"HttpSendRequest\" condition: $a and $b }",
         "广告软件特征"},
        {"YARA_RULE_004", "YARA",
         "rule Ransomware { strings: $a = \"CryptEncrypt\" $b = \"FindFirstFile\" condition: $a and $b }",
         "勒索软件特征"},
        {"MD5_BLACKLIST_001", "MD5黑名单",
         "e3b0c44298fc1c149afbf4c8996fb924",
         "已知恶意文件MD5"},
    };
    for (int i = 0; i < 5; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "name",        rules[i].name);
        cJSON_AddStringToObject(obj, "rule_type",   rules[i].rtype);
        cJSON_AddStringToObject(obj, "pattern",     rules[i].pattern);
        cJSON_AddStringToObject(obj, "description", rules[i].desc);
        cJSON_AddNumberToObject(obj, "enabled",     1);
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* 模块表：名称、文件名、生成函数                                               */
/* ─────────────────────────────────────────────────────────────────────────── */

typedef cJSON *(*GenFunc)(void);

typedef struct {
    const char *table;    /* 数据库表名 */
    const char *filename; /* JSON 文件名 */
    GenFunc     gen;      /* 生成函数 */
} Module;

static const Module MODULES[] = {
    {"sys_info",        "sys_info.json",        gen_sys_info},
    {"net_info",        "net_info.json",         gen_net_info},
    {"disk_info",       "disk_info.json",        gen_disk_info},
    {"process_info",    "process_info.json",     gen_process_info},
    {"port_info",       "port_info.json",        gen_port_info},
    {"autorun_info",    "autorun_info.json",     gen_autorun_info},
    {"scheduled_task",  "scheduled_task.json",   gen_scheduled_task},
    {"driver_info",     "driver_info.json",      gen_driver_info},
    {"shared_resource", "shared_resource.json",  gen_shared_resource},
    {"browser_plugin",  "browser_plugin.json",   gen_browser_plugin},
    {"memory_status",   "memory_status.json",    gen_memory_status},
    {"kernel_module",   "kernel_module.json",    gen_kernel_module},
    {"process_memory",  "process_memory.json",   gen_process_memory},
    {"static_scan",     "static_scan.json",      gen_static_scan},
    {"cert_scan",       "cert_scan.json",        gen_cert_scan},
    {"dynamic_scan",    "dynamic_scan.json",     gen_dynamic_scan},
    {"file_assoc_scan", "file_assoc_scan.json",  gen_file_assoc_scan},
    {"sample_extract",  "sample_extract.json",   gen_sample_extract},
    {"audit_log",       "audit_log.json",        gen_audit_log},
    {"whitelist",       "whitelist.json",        gen_whitelist},
    {"custom_rules",    "custom_rules.json",     gen_custom_rules},
    {NULL, NULL, NULL}
};

/* ─────────────────────────────────────────────────────────────────────────── */
/* -a 模式：生成 JSON 文件                                                      */
/* ─────────────────────────────────────────────────────────────────────────── */

static int cmd_generate(const char *out_dir)
{
    mkdir_p(out_dir);
    int total = 0;
    for (int i = 0; MODULES[i].table; i++) {
        cJSON *data = MODULES[i].gen();
        int cnt = cJSON_GetArraySize(data);
        if (write_json_file(out_dir, MODULES[i].filename, data) == 0)
            printf("  [生成] %-30s (%d 条)\n", MODULES[i].filename, cnt);
        else
            fprintf(stderr, "  [错误] 写入 %s 失败\n", MODULES[i].filename);
        total += cnt;
        cJSON_Delete(data);
    }
    printf("\n共生成 %d 个 JSON 文件，合计 %d 条记录，输出目录：%s\n",
           (int)(sizeof(MODULES)/sizeof(MODULES[0]) - 1), total, out_dir);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* -p 模式：将 JSON 文件导入 SQLite3                                            */
/* ─────────────────────────────────────────────────────────────────────────── */

/*
 * 根据 cJSON 对象动态构建 INSERT SQL 并执行。
 * 使用命名绑定参数 :key 形式，逐字段绑定。
 */
static int insert_row(sqlite3 *db, const char *table, cJSON *row)
{
    /* 收集所有字段名 */
    char cols[MAX_SQL_LEN] = {0};
    char vals[MAX_SQL_LEN] = {0};
    int  first = 1;

    cJSON *field = NULL;
    cJSON_ArrayForEach(field, row) {
        if (!first) { strcat(cols, ", "); strcat(vals, ", "); }
        strcat(cols, field->string);
        strcat(vals, ":");
        strcat(vals, field->string);
        first = 0;
    }

    char sql[MAX_SQL_LEN * 2];
    snprintf(sql, sizeof(sql), "INSERT INTO %s (%s) VALUES (%s)", table, cols, vals);

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "    prepare 失败: %s\n    SQL: %s\n",
                sqlite3_errmsg(db), sql);
        return -1;
    }

    /* 绑定每个字段值 */
    cJSON_ArrayForEach(field, row) {
        char param[64];
        snprintf(param, sizeof(param), ":%s", field->string);
        int idx = sqlite3_bind_parameter_index(stmt, param);
        if (idx == 0) continue;

        if (cJSON_IsString(field))
            sqlite3_bind_text(stmt, idx, field->valuestring, -1, SQLITE_TRANSIENT);
        else if (cJSON_IsNumber(field)) {
            /* 判断是否为整数 */
            double d = field->valuedouble;
            if (d == (long long)d)
                sqlite3_bind_int64(stmt, idx, (long long)d);
            else
                sqlite3_bind_double(stmt, idx, d);
        } else if (cJSON_IsNull(field))
            sqlite3_bind_null(stmt, idx);
        else if (cJSON_IsBool(field))
            sqlite3_bind_int(stmt, idx, cJSON_IsTrue(field) ? 1 : 0);
    }

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* 读取整个文件内容到字符串 */
static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, sz, f);
    buf[n] = '\0'; /* 确保 NUL 终止，覆盖之前的赋值 */
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

/* 根据文件名（去扩展名）查找对应表名 */
static const char *table_for_file(const char *filename)
{
    for (int i = 0; MODULES[i].table; i++) {
        if (strcmp(filename, MODULES[i].filename) == 0)
            return MODULES[i].table;
    }
    return NULL;
}

static int cmd_import(const char *json_dir, const char *db_path)
{
    /* 打开数据库 */
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "无法打开数据库: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    printf("数据库路径：%s\n", db_path);
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    DIR *dir = opendir(json_dir);
    if (!dir) {
        fprintf(stderr, "无法打开目录: %s\n", json_dir);
        sqlite3_close(db);
        return -1;
    }

    int total_inserted = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        /* 只处理 .json 文件 */
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        if (nlen < 5 || strcmp(name + nlen - 5, ".json") != 0) continue;

        const char *table = table_for_file(name);
        if (!table) {
            printf("  [跳过] %-30s (未知表名)\n", name);
            continue;
        }

        char filepath[MAX_PATH_LEN];
        snprintf(filepath, sizeof(filepath), "%s/%s", json_dir, name);
        char *content = read_file(filepath);
        if (!content) {
            fprintf(stderr, "  [错误] 读取 %s 失败\n", name);
            continue;
        }

        cJSON *root = cJSON_Parse(content);
        free(content);
        if (!root || !cJSON_IsArray(root)) {
            fprintf(stderr, "  [跳过] %-30s (JSON 解析失败或非数组)\n", name);
            if (root) cJSON_Delete(root);
            continue;
        }

        int inserted = 0, skipped = 0;
        sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
        cJSON *row = NULL;
        cJSON_ArrayForEach(row, root) {
            if (insert_row(db, table, row) == 0)
                inserted++;
            else
                skipped++;
        }
        sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
        cJSON_Delete(root);

        total_inserted += inserted;
        if (skipped > 0)
            printf("  [导入] %-30s 写入 %d 条，跳过 %d 条\n", name, inserted, skipped);
        else
            printf("  [导入] %-30s 写入 %d 条\n", name, inserted);
    }
    closedir(dir);
    sqlite3_close(db);
    printf("\n导入完成，共写入 %d 条记录到 %s\n", total_inserted, db_path);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* 自动查找数据库路径                                                           */
/* ─────────────────────────────────────────────────────────────────────────── */

static int find_db(const char *json_dir, char *out, size_t out_sz)
{
    const char *candidates[] = {
        "malware_detector.db",
        "./malware_detector.db",
        NULL
    };
    /* 先在 json_dir 下找 */
    char tmp[MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s/malware_detector.db", json_dir);
    candidates[0] = tmp;

    for (int i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0) {
            snprintf(out, out_sz, "%s", candidates[i]);
            return 0;
        }
    }
    /* 尝试 XDG 路径 */
    const char *home = getenv("HOME");
    if (home) {
        snprintf(tmp, sizeof(tmp),
                 "%s/.local/share/SecureDetect/恶意代码辅助检测系统/malware_detector.db", home);
        struct stat st;
        if (stat(tmp, &st) == 0) {
            snprintf(out, out_sz, "%s", tmp);
            return 0;
        }
    }
    return -1;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* 主函数                                                                       */
/* ─────────────────────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    printf(
        "用法:\n"
        "  %s -a [输出目录]           生成各模块 JSON 样例数据（默认 ./sample_data_c/）\n"
        "  %s -p <目录>               遍历目录下 JSON 文件并写入 SQLite3\n"
        "  %s -p <目录> --db <路径>   指定数据库路径\n"
        "\n"
        "示例:\n"
        "  %s -a\n"
        "  %s -a ./my_data\n"
        "  %s -p ./sample_data_c\n"
        "  %s -p ./sample_data_c --db /path/to/malware_detector.db\n",
        prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char *argv[])
{
    srand((unsigned)time(NULL));

    if (argc < 2) { usage(argv[0]); return 1; }

    /* 解析参数 */
    const char *mode      = NULL;  /* "-a" or "-p" */
    const char *arg_val   = NULL;  /* 目录 */
    const char *db_path   = NULL;  /* --db 参数 */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) {
            mode = "-a";
            if (i + 1 < argc && argv[i+1][0] != '-')
                arg_val = argv[++i];
            else
                arg_val = "./sample_data_c";
        } else if (strcmp(argv[i], "-p") == 0) {
            mode = "-p";
            if (i + 1 < argc)
                arg_val = argv[++i];
            else { fprintf(stderr, "-p 需要指定目录\n"); return 1; }
        } else if (strcmp(argv[i], "--db") == 0) {
            if (i + 1 < argc)
                db_path = argv[++i];
            else { fprintf(stderr, "--db 需要指定路径\n"); return 1; }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]); return 0;
        }
    }

    if (!mode) { usage(argv[0]); return 1; }

    if (strcmp(mode, "-a") == 0) {
        printf("=== 生成样例数据 → %s ===\n", arg_val);
        return cmd_generate(arg_val);
    }

    /* -p 模式 */
    char db_buf[MAX_PATH_LEN] = {0};
    if (!db_path) {
        if (find_db(arg_val, db_buf, sizeof(db_buf)) != 0) {
            fprintf(stderr,
                    "未找到 malware_detector.db，请通过 --db 参数指定数据库路径\n");
            return 1;
        }
        db_path = db_buf;
    }
    printf("=== 导入 JSON 数据 ← %s ===\n", arg_val);
    return cmd_import(arg_val, db_path);
}
