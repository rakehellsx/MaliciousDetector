#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
恶意代码辅助检测系统 - 数据生成工具
用法:
  python3 gen_data.py -a [输出目录]   生成各模块 JSON 样例数据（默认输出到 ./sample_data/）
  python3 gen_data.py -p <目录>       遍历目录下所有 JSON 文件并写入 SQLite3 数据库
"""

import argparse
import json
import os
import random
import sqlite3
import sys
from datetime import datetime, timedelta

# ──────────────────────────────────────────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────────────────────────────────────────

def now_str(offset_minutes=0):
    dt = datetime.now() - timedelta(minutes=offset_minutes)
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def rand_ip():
    return f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"

def rand_mac():
    return ":".join(f"{random.randint(0,255):02X}" for _ in range(6))

def rand_md5():
    import hashlib, uuid
    return hashlib.md5(uuid.uuid4().bytes).hexdigest()

def rand_sha256():
    import hashlib, uuid
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()

def rand_sha1():
    import hashlib, uuid
    return hashlib.sha1(uuid.uuid4().bytes).hexdigest()

def rand_risk():
    return random.choices(["高危", "中危", "低危", "正常"], weights=[1, 2, 3, 6])[0]

def rand_risk_en():
    return random.choices(["high", "medium", "low", "clean"], weights=[1, 2, 3, 6])[0]

def rand_date(days_back=365):
    d = datetime.now() - timedelta(days=random.randint(0, days_back))
    return d.strftime("%Y-%m-%d")

def rand_datetime(days_back=30):
    d = datetime.now() - timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59)
    )
    return d.strftime("%Y-%m-%d %H:%M:%S")

# ──────────────────────────────────────────────────────────────────────────────
# 各模块 JSON 数据生成
# ──────────────────────────────────────────────────────────────────────────────

def gen_sys_info():
    """系统基本信息（sys_info 表，key/value 格式）"""
    return [
        {"key": "操作系统",     "value": "Windows 10 专业版 64位 (10.0.19045)"},
        {"key": "计算机名称",   "value": "WORKSTATION-01"},
        {"key": "用户名",       "value": "Administrator"},
        {"key": "CPU型号",      "value": "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz"},
        {"key": "CPU核心数",    "value": "8核16线程"},
        {"key": "内存大小",     "value": "16 GB"},
        {"key": "系统盘",       "value": "C:\\ (SSD 512GB)"},
        {"key": "系统目录",     "value": "C:\\Windows\\System32"},
        {"key": "启动时间",     "value": rand_datetime(7)},
        {"key": "系统安装日期", "value": rand_date(365)},
        {"key": "BIOS版本",     "value": "American Megatrends Inc. F.20, 2023-06-15"},
        {"key": "主板型号",     "value": "ASUS PRIME Z490-A"},
        {"key": "序列号",       "value": f"SN{random.randint(100000,999999)}"},
        {"key": "防火墙状态",   "value": "已启用"},
        {"key": "UAC状态",      "value": "已启用"},
        {"key": "自动更新",     "value": "已启用"},
        {"key": "时区",         "value": "UTC+8 (中国标准时间)"},
        {"key": ".NET版本",     "value": "4.8.04084"},
        {"key": "PowerShell版本", "value": "5.1.19041.4648"},
    ]


def gen_net_info():
    """网络信息（net_info 表）"""
    adapters = [
        {"name": "以太网",     "ip": "192.168.1.100", "mask": "255.255.255.0",
         "gateway": "192.168.1.1", "mac": rand_mac(), "status": "已连接"},
        {"name": "以太网 2",   "ip": "10.10.0.50",    "mask": "255.255.0.0",
         "gateway": "10.10.0.1",   "mac": rand_mac(), "status": "已连接"},
        {"name": "WLAN",       "ip": "172.16.0.88",   "mask": "255.255.255.0",
         "gateway": "172.16.0.1",  "mac": rand_mac(), "status": "已断开"},
        {"name": "Loopback",   "ip": "127.0.0.1",     "mask": "255.0.0.0",
         "gateway": "",            "mac": "00:00:00:00:00:00", "status": "已连接"},
    ]
    return adapters


def gen_disk_info():
    """磁盘信息（disk_info 表）"""
    return [
        {"drive": "C:\\", "type": "固定磁盘", "filesystem": "NTFS",
         "total_gb": 512.0, "free_gb": 187.3, "used_pct": 63.4,
         "serial": f"SSD{random.randint(10000,99999)}"},
        {"drive": "D:\\", "type": "固定磁盘", "filesystem": "NTFS",
         "total_gb": 2048.0, "free_gb": 1204.7, "used_pct": 41.2,
         "serial": f"HDD{random.randint(10000,99999)}"},
        {"drive": "E:\\", "type": "可移动磁盘", "filesystem": "FAT32",
         "total_gb": 64.0, "free_gb": 32.1, "used_pct": 49.8,
         "serial": f"USB{random.randint(10000,99999)}"},
    ]


def gen_process_info():
    """进程信息（process_info 表）"""
    procs = [
        ("System",          4,    "NT AUTHORITY\\SYSTEM",   "C:\\Windows\\System32\\ntoskrnl.exe",  0.1,   2.4,  "运行中", "clean"),
        ("svchost.exe",     1234, "NT AUTHORITY\\SYSTEM",   "C:\\Windows\\System32\\svchost.exe",   0.3,  18.2,  "运行中", "clean"),
        ("explorer.exe",    3456, "WORKSTATION-01\\Admin",  "C:\\Windows\\explorer.exe",            1.2,  52.6,  "运行中", "clean"),
        ("chrome.exe",      5678, "WORKSTATION-01\\Admin",  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", 3.5, 312.4, "运行中", "clean"),
        ("python3.exe",     7890, "WORKSTATION-01\\Admin",  "C:\\Python39\\python3.exe",            0.8,  24.1,  "运行中", "clean"),
        ("svchost32.exe",   9012, "NT AUTHORITY\\SYSTEM",   "C:\\Windows\\Temp\\svchost32.exe",     8.7,  64.3,  "运行中", "高危"),
        ("update.exe",      1111, "WORKSTATION-01\\Admin",  "C:\\Users\\Admin\\AppData\\Roaming\\update.exe", 2.1, 12.8, "运行中", "中危"),
        ("lsass.exe",       888,  "NT AUTHORITY\\SYSTEM",   "C:\\Windows\\System32\\lsass.exe",     0.2,   8.6,  "运行中", "clean"),
        ("winlogon.exe",    600,  "NT AUTHORITY\\SYSTEM",   "C:\\Windows\\System32\\winlogon.exe",  0.1,   4.2,  "运行中", "clean"),
        ("taskmgr.exe",     4321, "WORKSTATION-01\\Admin",  "C:\\Windows\\System32\\taskmgr.exe",   0.5,  16.3,  "运行中", "clean"),
        ("notepad.exe",     6543, "WORKSTATION-01\\Admin",  "C:\\Windows\\System32\\notepad.exe",   0.0,   4.1,  "运行中", "clean"),
        ("cmd.exe",         7654, "WORKSTATION-01\\Admin",  "C:\\Windows\\System32\\cmd.exe",       0.0,   2.3,  "运行中", "clean"),
        ("powershell.exe",  8765, "WORKSTATION-01\\Admin",  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 1.1, 38.2, "运行中", "中危"),
        ("wscript.exe",     2233, "WORKSTATION-01\\Admin",  "C:\\Windows\\System32\\wscript.exe",   0.3,   6.7,  "运行中", "中危"),
        ("spoolsv.exe",     1560, "NT AUTHORITY\\SYSTEM",   "C:\\Windows\\System32\\spoolsv.exe",   0.1,  10.2,  "运行中", "clean"),
    ]
    result = []
    for name, pid, user, path, cpu, mem, status, risk in procs:
        result.append({
            "pid": pid, "name": name, "path": path, "user": user,
            "cpu_pct": cpu, "mem_mb": mem, "status": status, "risk": risk
        })
    return result


def gen_port_info():
    """端口信息（port_info 表）"""
    ports = [
        ("TCP", "0.0.0.0",     80,   "",          0,    "LISTEN",      "nginx.exe",      1234, "clean"),
        ("TCP", "0.0.0.0",     443,  "",          0,    "LISTEN",      "nginx.exe",      1234, "clean"),
        ("TCP", "0.0.0.0",     3389, "",          0,    "LISTEN",      "svchost.exe",    888,  "中危"),
        ("TCP", "192.168.1.100", 49152, "192.168.1.200", 445, "ESTABLISHED", "System", 4, "clean"),
        ("TCP", "192.168.1.100", 49200, "8.8.8.8",  53,   "ESTABLISHED", "chrome.exe",  5678, "clean"),
        ("TCP", "0.0.0.0",     4444, "",          0,    "LISTEN",      "svchost32.exe", 9012, "高危"),
        ("UDP", "0.0.0.0",     5353, "",          0,    "LISTEN",      "svchost.exe",   1234, "clean"),
        ("TCP", "127.0.0.1",   8080, "",          0,    "LISTEN",      "python3.exe",   7890, "clean"),
        ("TCP", "192.168.1.100", 49300, "10.10.0.1", 22, "ESTABLISHED", "putty.exe",   3456, "clean"),
        ("UDP", "0.0.0.0",     137,  "",          0,    "LISTEN",      "System",        4,    "clean"),
        ("TCP", "0.0.0.0",     1433, "",          0,    "LISTEN",      "sqlservr.exe",  2345, "中危"),
        ("TCP", "192.168.1.100", 49400, "185.220.101.1", 1080, "ESTABLISHED", "update.exe", 1111, "高危"),
    ]
    result = []
    for proto, lip, lport, rip, rport, state, proc, pid, risk in ports:
        result.append({
            "protocol": proto, "local_ip": lip, "local_port": lport,
            "remote_ip": rip, "remote_port": rport, "state": state,
            "process_name": proc, "pid": pid, "risk": risk
        })
    return result


def gen_autorun_info():
    """自启动项（autorun_info 表）"""
    return [
        # 注册表启动项
        {"type": "reg", "name": "SecurityHealth",
         "reg_path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "value": "SecurityHealth", "cmd": "C:\\Windows\\System32\\SecurityHealthSystray.exe",
         "publisher": "Microsoft Corporation", "risk": "正常"},
        {"type": "reg", "name": "OneDrive",
         "reg_path": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "value": "OneDrive", "cmd": "C:\\Users\\Admin\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background",
         "publisher": "Microsoft Corporation", "risk": "正常"},
        {"type": "reg", "name": "Updater",
         "reg_path": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "value": "Updater", "cmd": "C:\\Users\\Admin\\AppData\\Roaming\\update.exe --silent",
         "publisher": "Unknown", "risk": "高危"},
        {"type": "reg", "name": "SvcHelper",
         "reg_path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
         "value": "SvcHelper", "cmd": "C:\\Windows\\Temp\\svchost32.exe -k netsvcs",
         "publisher": "", "risk": "高危"},
        # 启动文件夹
        {"type": "folder", "name": "TeamViewer.lnk",
         "reg_path": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
         "value": "", "cmd": "C:\\Program Files\\TeamViewer\\TeamViewer.exe",
         "publisher": "TeamViewer GmbH", "risk": "正常"},
        {"type": "folder", "name": "malware.lnk",
         "reg_path": "C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
         "value": "", "cmd": "C:\\Users\\Admin\\AppData\\Local\\Temp\\malware.exe",
         "publisher": "", "risk": "高危"},
        # 右键菜单
        {"type": "menu", "name": "7-Zip",
         "reg_path": "HKCR\\*\\shellex\\ContextMenuHandlers\\7-Zip",
         "value": "", "cmd": "C:\\Program Files\\7-Zip\\7-zip.dll",
         "publisher": "Igor Pavlov", "risk": "正常"},
        {"type": "menu", "name": "ShellExt",
         "reg_path": "HKCR\\*\\shellex\\ContextMenuHandlers\\ShellExt",
         "value": "", "cmd": "C:\\Windows\\Temp\\shellext.dll",
         "publisher": "", "risk": "中危"},
        # 系统调试器
        {"type": "debugger", "name": "notepad.exe",
         "reg_path": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe",
         "value": "Debugger", "cmd": "C:\\Windows\\Temp\\svchost32.exe",
         "publisher": "", "risk": "高危"},
    ]


def gen_scheduled_task():
    """计划任务（scheduled_task 表）"""
    return [
        {"name": "MicrosoftEdgeUpdateTaskMachineCore",
         "path": "\\Microsoft\\EdgeUpdate\\",
         "trigger": "每天 09:00",
         "action": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe /c",
         "status": "就绪", "last_run": rand_datetime(3), "risk": "正常"},
        {"name": "WindowsDefenderScheduledScan",
         "path": "\\Microsoft\\Windows Defender\\",
         "trigger": "每周日 02:00",
         "action": "C:\\Program Files\\Windows Defender\\MpCmdRun.exe -Scan -ScanType 2",
         "status": "就绪", "last_run": rand_datetime(7), "risk": "正常"},
        {"name": "GoogleUpdateTaskMachineCore",
         "path": "\\GoogleUpdate\\",
         "trigger": "每天 08:00",
         "action": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c",
         "status": "就绪", "last_run": rand_datetime(1), "risk": "正常"},
        {"name": "SysMonitor",
         "path": "\\Custom\\",
         "trigger": "系统启动时",
         "action": "C:\\Windows\\Temp\\svchost32.exe --monitor",
         "status": "运行中", "last_run": rand_datetime(0), "risk": "高危"},
        {"name": "BackupTask",
         "path": "\\Custom\\",
         "trigger": "每天 23:00",
         "action": "C:\\Users\\Admin\\AppData\\Roaming\\backup.bat",
         "status": "就绪", "last_run": rand_datetime(1), "risk": "中危"},
        {"name": "WindowsUpdateCheck",
         "path": "\\Microsoft\\Windows\\UpdateOrchestrator\\",
         "trigger": "每天 03:00",
         "action": "C:\\Windows\\System32\\UsoClient.exe StartScan",
         "status": "就绪", "last_run": rand_datetime(2), "risk": "正常"},
    ]


def gen_driver_info():
    """驱动信息（driver_info 表）"""
    return [
        {"name": "ntfs.sys",       "type": "内核驱动", "publisher": "Microsoft Corporation",
         "modified_time": rand_date(180), "path": "C:\\Windows\\System32\\drivers\\ntfs.sys",
         "is_signed": 1, "risk": "正常"},
        {"name": "tcpip.sys",      "type": "内核驱动", "publisher": "Microsoft Corporation",
         "modified_time": rand_date(180), "path": "C:\\Windows\\System32\\drivers\\tcpip.sys",
         "is_signed": 1, "risk": "正常"},
        {"name": "ndis.sys",       "type": "内核驱动", "publisher": "Microsoft Corporation",
         "modified_time": rand_date(180), "path": "C:\\Windows\\System32\\drivers\\ndis.sys",
         "is_signed": 1, "risk": "正常"},
        {"name": "nvlddmkm.sys",   "type": "设备驱动", "publisher": "NVIDIA Corporation",
         "modified_time": rand_date(90),  "path": "C:\\Windows\\System32\\drivers\\nvlddmkm.sys",
         "is_signed": 1, "risk": "正常"},
        {"name": "360AntiHacker64.sys", "type": "第三方", "publisher": "360 Software",
         "modified_time": rand_date(30),  "path": "C:\\Program Files\\360\\360Safe\\deepscan\\360AntiHacker64.sys",
         "is_signed": 1, "risk": "正常"},
        {"name": "rootkit.sys",    "type": "内核驱动", "publisher": "",
         "modified_time": rand_date(7),   "path": "C:\\Windows\\Temp\\rootkit.sys",
         "is_signed": 0, "risk": "高危"},
        {"name": "hookdrv.sys",    "type": "第三方",   "publisher": "Unknown",
         "modified_time": rand_date(14),  "path": "C:\\Windows\\System32\\drivers\\hookdrv.sys",
         "is_signed": 0, "risk": "中危"},
        {"name": "WdFilter.sys",   "type": "内核驱动", "publisher": "Microsoft Corporation",
         "modified_time": rand_date(60),  "path": "C:\\Windows\\System32\\drivers\\wd\\WdFilter.sys",
         "is_signed": 1, "risk": "正常"},
    ]


def gen_shared_resource():
    """共享资源（shared_resource 表）"""
    return [
        {"name": "ADMIN$",  "path": "C:\\Windows",  "type": "系统共享",
         "permission": "完全控制", "connected": 0, "risk": "正常"},
        {"name": "C$",      "path": "C:\\",          "type": "系统共享",
         "permission": "完全控制", "connected": 1, "risk": "中危"},
        {"name": "IPC$",    "path": "",              "type": "IPC共享",
         "permission": "读取",    "connected": 0, "risk": "正常"},
        {"name": "Share",   "path": "D:\\Share",     "type": "用户共享",
         "permission": "读写",    "connected": 2, "risk": "正常"},
        {"name": "Backup",  "path": "D:\\Backup",    "type": "用户共享",
         "permission": "完全控制","connected": 0, "risk": "正常"},
        {"name": "Temp",    "path": "C:\\Windows\\Temp", "type": "用户共享",
         "permission": "完全控制","connected": 3, "risk": "高危"},
    ]


def gen_browser_plugin():
    """浏览器插件（browser_plugin 表）"""
    return [
        {"browser": "Chrome",  "name": "Google Docs Offline",
         "version": "1.65.0",  "publisher": "Google LLC",           "status": "已启用", "risk": "正常"},
        {"browser": "Chrome",  "name": "AdBlock",
         "version": "5.18.0",  "publisher": "AdBlock",              "status": "已启用", "risk": "正常"},
        {"browser": "Chrome",  "name": "Unknown Extension",
         "version": "0.1.0",   "publisher": "Unknown",              "status": "已启用", "risk": "高危"},
        {"browser": "Edge",    "name": "Microsoft Editor",
         "version": "3.0.14",  "publisher": "Microsoft Corporation","status": "已启用", "risk": "正常"},
        {"browser": "Edge",    "name": "Shopping Helper",
         "version": "2.3.1",   "publisher": "Unknown",              "status": "已禁用", "risk": "中危"},
        {"browser": "Firefox", "name": "uBlock Origin",
         "version": "1.56.0",  "publisher": "Raymond Hill",         "status": "已启用", "risk": "正常"},
        {"browser": "Firefox", "name": "Tampermonkey",
         "version": "5.0.0",   "publisher": "Jan Biniok",           "status": "已启用", "risk": "正常"},
        {"browser": "IE",      "name": "Adobe Flash Player",
         "version": "32.0.0",  "publisher": "Adobe Inc.",           "status": "已禁用", "risk": "中危"},
    ]


def gen_memory_status():
    """内存状态（memory_status 表）"""
    total = 16384
    used  = random.randint(6000, 12000)
    avail = total - used
    return [{
        "total_mb":   total,
        "used_mb":    used,
        "avail_mb":   avail,
        "virtual_mb": 32768,
        "page_file":  "C:\\pagefile.sys (4096MB)"
    }]


def gen_kernel_module():
    """内核模块（kernel_module 表）"""
    modules = [
        ("ntoskrnl.exe", "0xFFFFF80000000000", "0x00A00000", "LDRP_ENTRY_PROCESSED", "C:\\Windows\\System32\\ntoskrnl.exe", 1),
        ("hal.dll",      "0xFFFFF80000B00000", "0x00080000", "LDRP_ENTRY_PROCESSED", "C:\\Windows\\System32\\hal.dll", 1),
        ("ntfs.sys",     "0xFFFFF88000100000", "0x00200000", "LDRP_ENTRY_PROCESSED", "C:\\Windows\\System32\\drivers\\ntfs.sys", 1),
        ("tcpip.sys",    "0xFFFFF88001000000", "0x00300000", "LDRP_ENTRY_PROCESSED", "C:\\Windows\\System32\\drivers\\tcpip.sys", 1),
        ("ndis.sys",     "0xFFFFF88001400000", "0x00180000", "LDRP_ENTRY_PROCESSED", "C:\\Windows\\System32\\drivers\\ndis.sys", 1),
        ("rootkit.sys",  "0xFFFFF88002000000", "0x00010000", "LDRP_ENTRY_PROCESSED", "C:\\Windows\\Temp\\rootkit.sys", 0),
        ("WdFilter.sys", "0xFFFFF88003000000", "0x00100000", "LDRP_ENTRY_PROCESSED", "C:\\Windows\\System32\\drivers\\wd\\WdFilter.sys", 1),
    ]
    result = []
    for i, (name, base, size, flags, path, trusted) in enumerate(modules):
        result.append({
            "name": name, "base_address": base, "image_size": size,
            "flags": flags, "idx": i + 1, "path": path, "is_trusted": trusted
        })
    return result


def gen_process_memory():
    """进程内存映像（process_memory 表）"""
    procs = [
        ("System",         4,    2,   8,    16,   0),
        ("svchost.exe",    1234, 18,  42,   128,  0),
        ("explorer.exe",   3456, 52,  120,  512,  0),
        ("chrome.exe",     5678, 312, 480,  2048, 0),
        ("svchost32.exe",  9012, 64,  128,  256,  1),
        ("lsass.exe",      888,  8,   24,   64,   0),
        ("update.exe",     1111, 12,  28,   96,   1),
        ("powershell.exe", 8765, 38,  64,   256,  0),
    ]
    result = []
    for name, pid, priv, ws, virt, inject in procs:
        result.append({
            "name": name, "pid": pid,
            "private_mb": priv, "working_set_mb": ws,
            "virtual_mb": virt, "suspicious_inject": inject
        })
    return result


def gen_static_scan():
    """静态检测结果（static_scan 表）"""
    files = [
        ("C:\\Windows\\Temp\\svchost32.exe", "svchost32.exe", 245760, "PE32",
         rand_md5(), rand_sha1(), rand_sha256(),
         "2025-03-15 08:22:11", "Unknown", "high", "Trojan.Generic.12345",
         "PE结构异常，存在加壳特征，导入表包含可疑API",
         '[{"section":".text","vsize":163840,"rsize":163840},{"section":".data","vsize":8192,"rsize":8192}]',
         "CreateRemoteThread,VirtualAllocEx,WriteProcessMemory",
         '[{"rule":"YARA_RULE_001","desc":"疑似远控木马","hit":true},{"rule":"YARA_RULE_002","desc":"进程注入特征","hit":true}]'),
        ("C:\\Users\\Admin\\AppData\\Roaming\\update.exe", "update.exe", 102400, "PE32",
         rand_md5(), rand_sha1(), rand_sha256(),
         "2025-09-01 14:33:00", "Unknown", "medium", "Adware.Generic",
         "无数字签名，存在可疑网络连接行为",
         '[{"section":".text","vsize":65536,"rsize":65536}]',
         "WinInet,HttpSendRequest",
         '[{"rule":"YARA_RULE_003","desc":"广告软件特征","hit":true}]'),
        ("C:\\Windows\\System32\\notepad.exe", "notepad.exe", 204800, "PE32+",
         rand_md5(), rand_sha1(), rand_sha256(),
         "2023-04-11 09:00:00", "Microsoft Corporation", "clean", "",
         "系统文件，数字签名有效，未发现威胁",
         '[{"section":".text","vsize":131072,"rsize":131072}]',
         "CreateFile,ReadFile,WriteFile",
         '[]'),
        ("C:\\Users\\Admin\\Desktop\\readme.pdf.exe", "readme.pdf.exe", 51200, "PE32",
         rand_md5(), rand_sha1(), rand_sha256(),
         "2025-10-20 20:11:55", "", "high", "Ransomware.WannaCry.Variant",
         "双扩展名欺骗，无签名，包含加密勒索特征",
         '[{"section":".text","vsize":32768,"rsize":32768},{"section":".rsrc","vsize":4096,"rsize":4096}]',
         "CryptEncrypt,FindFirstFile,DeleteFile",
         '[{"rule":"YARA_RULE_004","desc":"勒索软件特征","hit":true}]'),
        ("C:\\Program Files\\7-Zip\\7z.exe", "7z.exe", 1048576, "PE32+",
         rand_md5(), rand_sha1(), rand_sha256(),
         "2024-06-01 00:00:00", "Igor Pavlov", "clean", "",
         "已知安全软件，数字签名有效",
         '[{"section":".text","vsize":524288,"rsize":524288}]',
         "CreateFile,ReadFile,WriteFile,SetFileAttributes",
         '[]'),
    ]
    result = []
    for (fp, fn, fs, ft, md5, sha1, sha256, ct, pub, risk, vname, conc, pe, strings, rules) in files:
        result.append({
            "file_path": fp, "file_name": fn, "file_size": fs, "file_type": ft,
            "md5": md5, "sha1": sha1, "sha256": sha256,
            "compile_time": ct, "publisher": pub,
            "pe_info": pe, "strings_info": strings, "rule_hits": rules,
            "risk_level": risk, "virus_name": vname, "conclusion": conc,
            "scan_time": rand_datetime(7)
        })
    return result


def gen_cert_scan():
    """数字证书检测（cert_scan 表，使用表实际字段）"""
    return [
        {"file_path": "C:\\Windows\\System32\\notepad.exe",
         "has_signature": 1, "signature_valid": 1, "file_tampered": 0,
         "subject": "Microsoft Corporation", "issuer": "Microsoft Root CA",
         "serial_number": "3300000266", "not_before": "2023-04-11 09:00:00",
         "not_after": "2025-04-11 09:00:00", "not_expired": 1,
         "hash_algorithm": "SHA256", "thumbprint_sha1": rand_sha1(),
         "thumbprint_sha256": rand_sha256(), "verify_result": "有效"},
        {"file_path": "C:\\Windows\\Temp\\svchost32.exe",
         "has_signature": 0, "signature_valid": 0, "file_tampered": 0,
         "subject": "", "issuer": "",
         "serial_number": "", "not_before": "",
         "not_after": "", "not_expired": 0,
         "hash_algorithm": "", "thumbprint_sha1": "",
         "thumbprint_sha256": "", "verify_result": "无签名"},
        {"file_path": "C:\\Users\\Admin\\Desktop\\readme.pdf.exe",
         "has_signature": 0, "signature_valid": 0, "file_tampered": 0,
         "subject": "", "issuer": "",
         "serial_number": "", "not_before": "",
         "not_after": "", "not_expired": 0,
         "hash_algorithm": "", "thumbprint_sha1": "",
         "thumbprint_sha256": "", "verify_result": "无签名"},
        {"file_path": "C:\\Users\\Admin\\AppData\\Roaming\\update.exe",
         "has_signature": 1, "signature_valid": 0, "file_tampered": 1,
         "subject": "Unknown Publisher", "issuer": "Unknown CA",
         "serial_number": "0001", "not_before": "2022-01-01 00:00:00",
         "not_after": "2023-01-01 00:00:00", "not_expired": 0,
         "hash_algorithm": "SHA1", "thumbprint_sha1": rand_sha1(),
         "thumbprint_sha256": rand_sha256(), "verify_result": "证书过期"},
        {"file_path": "C:\\Program Files\\7-Zip\\7z.exe",
         "has_signature": 1, "signature_valid": 1, "file_tampered": 0,
         "subject": "Igor Pavlov", "issuer": "Sectigo RSA Code Signing CA",
         "serial_number": "AB12CD34EF56", "not_before": "2024-06-01 00:00:00",
         "not_after": "2026-06-01 00:00:00", "not_expired": 1,
         "hash_algorithm": "SHA256", "thumbprint_sha1": rand_sha1(),
         "thumbprint_sha256": rand_sha256(), "verify_result": "有效"},
    ]


def gen_dynamic_scan():
    """动态行为检测（dynamic_scan 表）"""
    sample = "C:\\Windows\\Temp\\svchost32.exe"
    return [
        # 注册表操作
        {"sample_path": sample, "behavior_type": "registry", "action_type": "SetValue",
         "source_proc": "svchost32.exe", "target_path": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcHelper",
         "detail": "写入启动项", "risk_level": "high", "parent_pid": 0, "pid": 9012},
        {"sample_path": sample, "behavior_type": "registry", "action_type": "CreateKey",
         "source_proc": "svchost32.exe", "target_path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\maldrv",
         "detail": "创建服务注册表项", "risk_level": "high", "parent_pid": 0, "pid": 9012},
        # 文件行为
        {"sample_path": sample, "behavior_type": "file", "action_type": "Write",
         "source_proc": "svchost32.exe", "target_path": "C:\\Windows\\System32\\drivers\\maldrv.sys",
         "detail": "写入驱动文件", "risk_level": "high", "parent_pid": 0, "pid": 9012},
        {"sample_path": sample, "behavior_type": "file", "action_type": "Create",
         "source_proc": "svchost32.exe", "target_path": "C:\\Users\\Admin\\AppData\\Roaming\\config.dat",
         "detail": "创建配置文件", "risk_level": "medium", "parent_pid": 0, "pid": 9012},
        # 进程行为
        {"sample_path": sample, "behavior_type": "process", "action_type": "Inject",
         "source_proc": "svchost32.exe", "target_path": "lsass.exe",
         "detail": "进程注入 lsass.exe", "risk_level": "high", "parent_pid": 9012, "pid": 888},
        {"sample_path": sample, "behavior_type": "process", "action_type": "Create",
         "source_proc": "svchost32.exe", "target_path": "cmd.exe",
         "detail": "创建子进程 cmd.exe", "risk_level": "medium", "parent_pid": 9012, "pid": 7654},
        # 网络行为
        {"sample_path": sample, "behavior_type": "network", "action_type": "Connect",
         "source_proc": "svchost32.exe", "target_path": "185.220.101.1:4444",
         "detail": "连接 C2 服务器", "risk_level": "high", "parent_pid": 0, "pid": 9012},
        {"sample_path": sample, "behavior_type": "network", "action_type": "DNS",
         "source_proc": "svchost32.exe", "target_path": "evil-c2.example.com",
         "detail": "DNS 查询可疑域名", "risk_level": "high", "parent_pid": 0, "pid": 9012},
    ]


def gen_file_assoc_scan():
    """文件关联检测（file_assoc_scan 表）"""
    return [
        {"ext": ".exe", "assoc_type": "正常",
         "original_cmd": "\"C:\\Windows\\System32\\cmd.exe\" \"%1\" %*",
         "current_cmd":  "\"C:\\Windows\\System32\\cmd.exe\" \"%1\" %*",
         "risk_level": "clean"},
        {"ext": ".bat", "assoc_type": "正常",
         "original_cmd": "C:\\Windows\\System32\\cmd.exe /c \"%1\" %*",
         "current_cmd":  "C:\\Windows\\System32\\cmd.exe /c \"%1\" %*",
         "risk_level": "clean"},
        {"ext": ".txt", "assoc_type": "篡改",
         "original_cmd": "C:\\Windows\\System32\\notepad.exe %1",
         "current_cmd":  "C:\\Windows\\Temp\\svchost32.exe --open %1",
         "risk_level": "high"},
        {"ext": ".pdf", "assoc_type": "篡改",
         "original_cmd": "\"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe\" \"%1\"",
         "current_cmd":  "C:\\Users\\Admin\\AppData\\Roaming\\update.exe --pdf \"%1\"",
         "risk_level": "high"},
        {"ext": ".html", "assoc_type": "正常",
         "original_cmd": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" -- \"%1\"",
         "current_cmd":  "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" -- \"%1\"",
         "risk_level": "clean"},
        {"ext": ".docx", "assoc_type": "正常",
         "original_cmd": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"%1\"",
         "current_cmd":  "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"%1\"",
         "risk_level": "clean"},
    ]


def gen_sample_extract():
    """样本提取（sample_extract 表）"""
    return [
        {"source_path": "C:\\Windows\\Temp\\svchost32.exe",
         "extract_type": "可执行文件",
         "sample_path": "D:\\Samples\\svchost32_20251101.exe",
         "md5": rand_md5(), "sha256": rand_sha256(),
         "original_mtime": rand_datetime(7), "original_ctime": rand_datetime(30),
         "note": "高危样本，疑似远控木马"},
        {"source_path": "C:\\Users\\Admin\\Desktop\\readme.pdf.exe",
         "extract_type": "可执行文件",
         "sample_path": "D:\\Samples\\readme.pdf.exe_20251101.exe",
         "md5": rand_md5(), "sha256": rand_sha256(),
         "original_mtime": rand_datetime(3), "original_ctime": rand_datetime(3),
         "note": "双扩展名欺骗，疑似勒索软件"},
        {"source_path": "C:\\Users\\Admin\\AppData\\Roaming\\update.exe",
         "extract_type": "可执行文件",
         "sample_path": "D:\\Samples\\update_20251101.exe",
         "md5": rand_md5(), "sha256": rand_sha256(),
         "original_mtime": rand_datetime(14), "original_ctime": rand_datetime(60),
         "note": "广告软件"},
    ]


def gen_audit_log():
    """操作日志（audit_log 表）"""
    logs = []
    users = [
        ("system_admin", "admin"),
        ("sec_admin",    "secadmin"),
        ("auditor",      "auditor"),
    ]
    actions = [
        ("登录",   "用户登录系统",       "success"),
        ("扫描",   "执行静态检测扫描",   "success"),
        ("导出",   "导出检测报告",       "success"),
        ("设置",   "修改扫描策略配置",   "success"),
        ("白名单", "添加白名单条目",     "success"),
        ("登出",   "用户登出系统",       "success"),
        ("登录",   "用户登录失败",       "fail"),
        ("规则",   "新增自定义规则",     "success"),
    ]
    for i in range(20):
        role, username = random.choice(users)
        action, detail, result = random.choice(actions)
        logs.append({
            "role": role, "username": username,
            "action": action, "detail": detail,
            "result": result,
            "ip_address": rand_ip(),
            "timestamp": rand_datetime(30)
        })
    return sorted(logs, key=lambda x: x["timestamp"], reverse=True)


def gen_whitelist():
    """白名单（whitelist 表）"""
    return [
        {"path": "C:\\Windows\\System32\\notepad.exe", "md5": rand_md5(),
         "note": "系统文件", "added_by": "admin"},
        {"path": "C:\\Program Files\\7-Zip\\7z.exe", "md5": rand_md5(),
         "note": "已知安全软件", "added_by": "secadmin"},
        {"path": "", "md5": rand_md5(),
         "note": "MD5白名单", "added_by": "admin"},
    ]


def gen_custom_rules():
    """自定义规则（custom_rules 表）"""
    return [
        {"name": "YARA_RULE_001", "rule_type": "YARA",
         "pattern": "rule TrojanGeneric { strings: $a = \"CreateRemoteThread\" condition: $a }",
         "description": "疑似远控木马特征", "enabled": 1},
        {"name": "YARA_RULE_002", "rule_type": "YARA",
         "pattern": "rule ProcessInjection { strings: $a = \"VirtualAllocEx\" $b = \"WriteProcessMemory\" condition: $a and $b }",
         "description": "进程注入特征", "enabled": 1},
        {"name": "YARA_RULE_003", "rule_type": "YARA",
         "pattern": "rule Adware { strings: $a = \"WinInet\" $b = \"HttpSendRequest\" condition: $a and $b }",
         "description": "广告软件特征", "enabled": 1},
        {"name": "YARA_RULE_004", "rule_type": "YARA",
         "pattern": "rule Ransomware { strings: $a = \"CryptEncrypt\" $b = \"FindFirstFile\" condition: $a and $b }",
         "description": "勒索软件特征", "enabled": 1},
        {"name": "MD5_BLACKLIST_001", "rule_type": "MD5黑名单",
         "pattern": "e3b0c44298fc1c149afbf4c8996fb924",
         "description": "已知恶意文件MD5", "enabled": 1},
    ]


# ──────────────────────────────────────────────────────────────────────────────
# 模块注册表：模块名 → (生成函数, JSON文件名)
# ──────────────────────────────────────────────────────────────────────────────

MODULES = {
    "sys_info":        (gen_sys_info,        "sys_info.json"),
    "net_info":        (gen_net_info,        "net_info.json"),
    "disk_info":       (gen_disk_info,       "disk_info.json"),
    "process_info":    (gen_process_info,    "process_info.json"),
    "port_info":       (gen_port_info,       "port_info.json"),
    "autorun_info":    (gen_autorun_info,    "autorun_info.json"),
    "scheduled_task":  (gen_scheduled_task,  "scheduled_task.json"),
    "driver_info":     (gen_driver_info,     "driver_info.json"),
    "shared_resource": (gen_shared_resource, "shared_resource.json"),
    "browser_plugin":  (gen_browser_plugin,  "browser_plugin.json"),
    "memory_status":   (gen_memory_status,   "memory_status.json"),
    "kernel_module":   (gen_kernel_module,   "kernel_module.json"),
    "process_memory":  (gen_process_memory,  "process_memory.json"),
    "static_scan":     (gen_static_scan,     "static_scan.json"),
    "cert_scan":       (gen_cert_scan,       "cert_scan.json"),
    "dynamic_scan":    (gen_dynamic_scan,    "dynamic_scan.json"),
    "file_assoc_scan": (gen_file_assoc_scan, "file_assoc_scan.json"),
    "sample_extract":  (gen_sample_extract,  "sample_extract.json"),
    "audit_log":       (gen_audit_log,       "audit_log.json"),
    "whitelist":       (gen_whitelist,       "whitelist.json"),
    "custom_rules":    (gen_custom_rules,    "custom_rules.json"),
}

# ──────────────────────────────────────────────────────────────────────────────
# -a：生成 JSON 文件
# ──────────────────────────────────────────────────────────────────────────────

def cmd_generate(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    total = 0
    for module, (gen_fn, filename) in MODULES.items():
        data = gen_fn()
        out_path = os.path.join(output_dir, filename)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"  [生成] {filename}  ({len(data)} 条)")
        total += len(data)
    print(f"\n共生成 {len(MODULES)} 个 JSON 文件，合计 {total} 条记录，输出目录：{output_dir}")


# ──────────────────────────────────────────────────────────────────────────────
# -p：将 JSON 文件写入 SQLite3
# ──────────────────────────────────────────────────────────────────────────────

# 每个表的插入 SQL（字段顺序与 JSON key 对应）
INSERT_SQL = {
    "sys_info": "INSERT OR REPLACE INTO sys_info(key, value) VALUES(:key, :value)",
    "net_info": """INSERT INTO net_info(name, ip, mask, gateway, mac, status)
                   VALUES(:name, :ip, :mask, :gateway, :mac, :status)""",
    "disk_info": """INSERT INTO disk_info(drive, type, filesystem, total_gb, free_gb, used_pct, serial)
                    VALUES(:drive, :type, :filesystem, :total_gb, :free_gb, :used_pct, :serial)""",
    "process_info": """INSERT INTO process_info(pid, name, path, user, cpu_pct, mem_mb, status, risk)
                       VALUES(:pid, :name, :path, :user, :cpu_pct, :mem_mb, :status, :risk)""",
    "port_info": """INSERT INTO port_info(protocol, local_ip, local_port, remote_ip, remote_port, state, process_name, pid, risk)
                    VALUES(:protocol, :local_ip, :local_port, :remote_ip, :remote_port, :state, :process_name, :pid, :risk)""",
    "autorun_info": """INSERT INTO autorun_info(type, name, reg_path, value, cmd, publisher, risk)
                       VALUES(:type, :name, :reg_path, :value, :cmd, :publisher, :risk)""",
    "scheduled_task": """INSERT INTO scheduled_task(name, path, trigger, action, status, last_run, risk)
                         VALUES(:name, :path, :trigger, :action, :status, :last_run, :risk)""",
    "driver_info": """INSERT INTO driver_info(name, type, publisher, modified_time, path, is_signed, risk)
                      VALUES(:name, :type, :publisher, :modified_time, :path, :is_signed, :risk)""",
    "shared_resource": """INSERT INTO shared_resource(name, path, type, permission, connected, risk)
                          VALUES(:name, :path, :type, :permission, :connected, :risk)""",
    "browser_plugin": """INSERT INTO browser_plugin(browser, name, version, publisher, status, risk)
                         VALUES(:browser, :name, :version, :publisher, :status, :risk)""",
    "memory_status": """INSERT INTO memory_status(total_mb, used_mb, avail_mb, virtual_mb, page_file)
                        VALUES(:total_mb, :used_mb, :avail_mb, :virtual_mb, :page_file)""",
    "kernel_module": """INSERT INTO kernel_module(name, base_address, image_size, flags, idx, path, is_trusted)
                        VALUES(:name, :base_address, :image_size, :flags, :idx, :path, :is_trusted)""",
    "process_memory": """INSERT INTO process_memory(name, pid, private_mb, working_set_mb, virtual_mb, suspicious_inject)
                         VALUES(:name, :pid, :private_mb, :working_set_mb, :virtual_mb, :suspicious_inject)""",
    "static_scan": """INSERT INTO static_scan(file_path, file_name, file_size, file_type, md5, sha1, sha256,
                      compile_time, publisher, pe_info, strings_info, rule_hits, risk_level, virus_name, conclusion, scan_time)
                      VALUES(:file_path, :file_name, :file_size, :file_type, :md5, :sha1, :sha256,
                      :compile_time, :publisher, :pe_info, :strings_info, :rule_hits, :risk_level, :virus_name, :conclusion, :scan_time)""",
    "cert_scan": """INSERT INTO cert_scan(file_path, has_signature, signature_valid, file_tampered,
                      subject, issuer, serial_number, not_before, not_after, not_expired,
                      hash_algorithm, thumbprint_sha1, thumbprint_sha256, verify_result)
                    VALUES(:file_path, :has_signature, :signature_valid, :file_tampered,
                      :subject, :issuer, :serial_number, :not_before, :not_after, :not_expired,
                      :hash_algorithm, :thumbprint_sha1, :thumbprint_sha256, :verify_result)""",
    "dynamic_scan": """INSERT INTO dynamic_scan(sample_path, behavior_type, action_type, source_proc, target_path, detail, risk_level, parent_pid, pid)
                       VALUES(:sample_path, :behavior_type, :action_type, :source_proc, :target_path, :detail, :risk_level, :parent_pid, :pid)""",
    "file_assoc_scan": """INSERT INTO file_assoc_scan(ext, assoc_type, original_cmd, current_cmd, risk_level)
                          VALUES(:ext, :assoc_type, :original_cmd, :current_cmd, :risk_level)""",
    "sample_extract": """INSERT INTO sample_extract(source_path, extract_type, sample_path, md5, sha256, original_mtime, original_ctime, note)
                         VALUES(:source_path, :extract_type, :sample_path, :md5, :sha256, :original_mtime, :original_ctime, :note)""",
    "audit_log": """INSERT INTO audit_log(role, username, action, detail, result, ip_address, timestamp)
                    VALUES(:role, :username, :action, :detail, :result, :ip_address, :timestamp)""",
    "whitelist": """INSERT INTO whitelist(path, md5, note, added_by)
                    VALUES(:path, :md5, :note, :added_by)""",
    "custom_rules": """INSERT INTO custom_rules(name, rule_type, pattern, description, enabled)
                       VALUES(:name, :rule_type, :pattern, :description, :enabled)""",
}

# cert_scan 表需要额外的字段兼容处理
CERT_SCAN_EXTRA_FIELDS = {
    "file_name": "", "signer": "", "issuer": "", "timestamp": "",
    "sign_status": "", "tamper_status": ""
}


def find_db(search_dirs):
    """在常见位置查找 SQLite 数据库文件"""
    candidates = [
        "malware_detector.db",
        os.path.join(os.path.expanduser("~"), "malware_detector.db"),
    ]
    for d in search_dirs:
        candidates.append(os.path.join(d, "malware_detector.db"))
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def cmd_import(json_dir, db_path=None):
    # 自动查找数据库
    if not db_path:
        db_path = find_db([json_dir, "."])
    if not db_path:
        print("未找到 malware_detector.db，请通过 --db 参数指定数据库路径")
        sys.exit(1)

    print(f"数据库路径：{db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # 遍历目录下所有 JSON 文件
    json_files = [f for f in os.listdir(json_dir) if f.endswith(".json")]
    if not json_files:
        print(f"目录 {json_dir} 下没有找到 JSON 文件")
        return

    total_inserted = 0
    for filename in sorted(json_files):
        # 根据文件名推断表名（去掉 .json 后缀）
        table = os.path.splitext(filename)[0]
        if table not in INSERT_SQL:
            print(f"  [跳过] {filename}  (未知表名 '{table}'，无对应 INSERT SQL)")
            continue

        filepath = os.path.join(json_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                rows = json.load(f)
        except Exception as e:
            print(f"  [错误] 读取 {filename} 失败：{e}")
            continue

        if not isinstance(rows, list):
            print(f"  [跳过] {filename}  (JSON 根节点不是数组)")
            continue

        sql = INSERT_SQL[table]
        inserted = 0
        skipped  = 0
        cur = conn.cursor()
        for row in rows:
            # 补全缺失字段为空字符串，避免 KeyError
            params = {k: row.get(k, "") for k in row}
            try:
                cur.execute(sql, params)
                inserted += 1
            except sqlite3.Error as e:
                skipped += 1
                if skipped == 1:
                    print(f"    警告：{e}（后续同类错误不再重复打印）")
        conn.commit()
        total_inserted += inserted
        print(f"  [导入] {filename:<30} 写入 {inserted} 条" +
              (f"，跳过 {skipped} 条" if skipped else ""))

    conn.close()
    print(f"\n导入完成，共写入 {total_inserted} 条记录到 {db_path}")


# ──────────────────────────────────────────────────────────────────────────────
# 入口
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="恶意代码辅助检测系统 - 数据生成工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 gen_data.py -a                    # 生成 JSON 到 ./sample_data/
  python3 gen_data.py -a ./my_data          # 生成 JSON 到 ./my_data/
  python3 gen_data.py -p ./sample_data      # 将 ./sample_data/ 下 JSON 写入数据库
  python3 gen_data.py -p ./my_data --db /path/to/malware_detector.db
  python3 gen_data.py -a && python3 gen_data.py -p ./sample_data  # 一键生成并导入
        """
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", dest="generate", nargs="?", const="./sample_data",
                       metavar="输出目录",
                       help="生成各模块 JSON 样例数据（默认输出到 ./sample_data/）")
    group.add_argument("-p", dest="import_dir", metavar="路径",
                       help="遍历指定目录的 JSON 文件并写入 SQLite3 数据库")
    parser.add_argument("--db", dest="db_path", metavar="数据库路径",
                        help="指定 SQLite3 数据库文件路径（-p 模式使用，默认自动查找）")

    args = parser.parse_args()

    if args.generate is not None:
        print(f"=== 生成样例数据 → {args.generate} ===")
        cmd_generate(args.generate)
    elif args.import_dir:
        if not os.path.isdir(args.import_dir):
            print(f"错误：目录不存在：{args.import_dir}")
            sys.exit(1)
        print(f"=== 导入 JSON 数据 ← {args.import_dir} ===")
        cmd_import(args.import_dir, args.db_path)


if __name__ == "__main__":
    main()
