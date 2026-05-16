#include "monitor.h"
#include <windows.h>
#include <shlobj.h>
#include <tchar.h>
#include <vector>
#include <string>
#include <algorithm>
#include <ctime>
#include <process.h>
#include <iostream>
#include <fstream>

static std::vector<std::string> g_watch_dirs;
static volatile bool g_running = false;
static HANDLE g_monitor_thread = NULL;
static FileChangeCallback g_callback = nullptr;
static void* g_callback_user = nullptr;
static CRITICAL_SECTION g_cs;
static std::vector<FirewallRule> g_firewall_rules;
static int g_next_rule_id = 1;
static FILE* g_log_file = nullptr;

static const char* VERSION = "1.0.0";

static void write_log(int level, const char* msg) {
    EnterCriticalSection(&g_cs);
    if (!g_log_file) {
        char log_path[MAX_PATH];
        GetModuleFileNameA(NULL, log_path, MAX_PATH);
        std::string log_dir = log_path;
        size_t pos = log_dir.rfind('\\');
        if (pos != std::string::npos) log_dir = log_dir.substr(0, pos);
        log_dir += "\\..\\data\\logs\\monitor.log";
        g_log_file = fopen(log_dir.c_str(), "a");
    }
    if (g_log_file) {
        time_t now = time(nullptr);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(g_log_file, "[%s] [%d] %s\n", time_str, level, msg);
        fflush(g_log_file);
    }
    LeaveCriticalSection(&g_cs);
}

struct WatchDirInfo {
    std::string path;
    HANDLE dir_handle;
    OVERLAPPED overlapped;
    char buffer[16384];
    bool active;
};

static std::vector<WatchDirInfo*> g_watch_infos;

static unsigned int __stdcall monitor_worker(void* param) {
    write_log(1, "Monitor thread started");
    std::vector<HANDLE> handles;
    for (auto* info : g_watch_infos) {
        if (info->dir_handle != INVALID_HANDLE_VALUE) {
            handles.push_back(info->dir_handle);
        }
    }
    while (g_running) {
        DWORD wait_result = WaitForMultipleObjects((DWORD)handles.size(), handles.data(), FALSE, 100);
        if (wait_result >= WAIT_OBJECT_0 && wait_result < WAIT_OBJECT_0 + handles.size()) {
            size_t idx = wait_result - WAIT_OBJECT_0;
            if (idx < g_watch_infos.size()) {
                WatchDirInfo* info = g_watch_infos[idx];
                DWORD bytes_returned;
                FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)info->buffer;
                while (ReadDirectoryChangesW(
                    info->dir_handle,
                    info->buffer,
                    sizeof(info->buffer),
                    TRUE,
                    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                    &bytes_returned,
                    &info->overlapped,
                    NULL))
                {
                    wchar_t* filename = (wchar_t*)malloc(MAX_PATH * sizeof(wchar_t));
                    if (filename) {
                        wcsncpy_s(filename, MAX_PATH, fni->FileName, MAX_PATH - 1);
                        char ansi_path[MAX_PATH];
                        WideCharToMultiByte(CP_ACP, 0, filename, -1, ansi_path, MAX_PATH, NULL, NULL);
                        char full_path[MAX_PATH];
                        sprintf_s(full_path, "%s\\%s", info->path.c_str(), ansi_path);
                        if (g_callback) {
                            int event_type = (fni->Action == FILE_ACTION_MODIFIED) ? 1 :
                                           (fni->Action == FILE_ACTION_ADDED) ? 2 : 3;
                            g_callback(full_path, event_type, g_callback_user);
                        }
                        if (!fni->NextEntryOffset) break;
                        fni = (FILE_NOTIFY_INFORMATION*)((char*)fni + fni->NextEntryOffset);
                        free(filename);
                    }
                }
            }
        }
        Sleep(10);
    }
    for (auto* info : g_watch_infos) {
        if (info->dir_handle != INVALID_HANDLE_VALUE) CloseHandle(info->dir_handle);
        delete info;
    }
    g_watch_infos.clear();
    write_log(1, "Monitor thread stopped");
    return 0;
}

MONITOR_API int init_monitor(const char* watched_dirs[], int dir_count) {
    InitializeCriticalSection(&g_cs);
    write_log(1, "Initializing file monitor");
    if (g_running) stop_monitor();
    g_watch_dirs.clear();
    for (int i = 0; i < dir_count; i++) {
        if (watched_dirs[i] && strlen(watched_dirs[i]) > 0) {
            g_watch_dirs.push_back(watched_dirs[i]);
        }
    }
    if (g_watch_dirs.empty()) {
        char sysdir[MAX_PATH];
        GetSystemDirectoryA(sysdir, MAX_PATH);
        g_watch_dirs.push_back(std::string(sysdir) + "\\System32");
        char userprofile[MAX_PATH];
        GetEnvironmentVariableA("USERPROFILE", userprofile, MAX_PATH);
        g_watch_dirs.push_back(std::string(userprofile) + "\\Downloads");
    }
    for (const auto& dir : g_watch_dirs) {
        WatchDirInfo* info = new WatchDirInfo();
        info->path = dir;
        info->dir_handle = CreateFileA(
            dir.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            NULL
        );
        if (info->dir_handle != INVALID_HANDLE_VALUE) {
            memset(&info->overlapped, 0, sizeof(OVERLAPPED));
            info->active = true;
            g_watch_infos.push_back(info);
            write_log(1, ("Watching: " + dir).c_str());
        } else {
            delete info;
            write_log(2, ("Failed to watch: " + dir).c_str());
        }
    }
    if (g_watch_infos.empty()) {
        write_log(2, "No directories could be watched");
        return 0;
    }
    g_running = true;
    g_monitor_thread = (HANDLE)_beginthreadex(NULL, 0, monitor_worker, NULL, 0, NULL);
    write_log(1, "Monitor initialized successfully");
    return 1;
}

MONITOR_API void stop_monitor(void) {
    if (!g_running) return;
    write_log(1, "Stopping file monitor");
    g_running = false;
    if (g_monitor_thread) {
        WaitForSingleObject(g_monitor_thread, 5000);
        CloseHandle(g_monitor_thread);
        g_monitor_thread = NULL;
    }
    for (auto* info : g_watch_infos) {
        if (info->dir_handle != INVALID_HANDLE_VALUE) CloseHandle(info->dir_handle);
        delete info;
    }
    g_watch_infos.clear();
    write_log(1, "Monitor stopped");
}

MONITOR_API int is_running(void) {
    return g_running ? 1 : 0;
}

MONITOR_API void set_file_callback(FileChangeCallback callback, void* user_data) {
    g_callback = callback;
    g_callback_user = user_data;
}

MONITOR_API int add_firewall_rule(const char* ip, int port, int direction, int action) {
    EnterCriticalSection(&g_cs);
    FirewallRule rule;
    strncpy(rule.ip, ip ? ip : "0.0.0.0", 63);
    rule.ip[63] = '\0';
    rule.port = port;
    rule.direction = direction;
    rule.action = action;
    rule.enabled = 1;
    g_firewall_rules.push_back(rule);
    int id = g_next_rule_id++;
    char cmd[512];
    if (direction == 0) {
        sprintf_s(cmd, "netsh advfirewall firewall add rule name=\"ShieldPro_%d\" dir=in action=%s remoteip=%s localport=%d",
            id, action == 0 ? "block" : "allow", ip, port);
    } else {
        sprintf_s(cmd, "netsh advfirewall firewall add rule name=\"ShieldPro_%d\" dir=out action=%s remoteip=%s remoteport=%d",
            id, action == 0 ? "block" : "allow", ip, port);
    }
    system(cmd);
    write_log(1, ("Added firewall rule: " + std::string(ip) + ":" + std::to_string(port)).c_str());
    LeaveCriticalSection(&g_cs);
    return id;
}

MONITOR_API int remove_firewall_rule(int rule_id) {
    EnterCriticalSection(&g_cs);
    char cmd[256];
    sprintf_s(cmd, "netsh advfirewall firewall delete rule name=\"ShieldPro_%d\"", rule_id);
    system(cmd);
    if (rule_id > 0 && rule_id < (int)g_firewall_rules.size()) {
        g_firewall_rules.erase(g_firewall_rules.begin() + rule_id - 1);
    }
    write_log(1, ("Removed firewall rule: " + std::to_string(rule_id)).c_str());
    LeaveCriticalSection(&g_cs);
    return 1;
}

MONITOR_API int get_firewall_rules(FirewallRule* rules, int max_rules) {
    EnterCriticalSection(&g_cs);
    int count = (int)g_firewall_rules.size();
    if (count > max_rules) count = max_rules;
    for (int i = 0; i < count; i++) {
        rules[i] = g_firewall_rules[i];
    }
    LeaveCriticalSection(&g_cs);
    return count;
}

MONITOR_API int get_firewall_rule_count(void) {
    return (int)g_firewall_rules.size();
}

MONITOR_API void clear_firewall_rules(void) {
    EnterCriticalSection(&g_cs);
    for (size_t i = 0; i < g_firewall_rules.size(); i++) {
        char cmd[256];
        sprintf_s(cmd, "netsh advfirewall firewall delete rule name=\"ShieldPro_%lu\"", (unsigned long)(i + 1));
        system(cmd);
    }
    g_firewall_rules.clear();
    write_log(1, "All firewall rules cleared");
    LeaveCriticalSection(&g_cs);
}

MONITOR_API int check_usb_devices(void) {
    char drives[256];
    GetLogicalDrives();
    DWORD mask = GetLogicalDrives();
    int count = 0;
    for (int i = 0; i < 26; i++) {
        if (mask & (1 << i)) {
            char drive[4] = { 'A' + i, ':', '\\', '\0' };
            UINT type = GetDriveTypeA(drive);
            if (type == DRIVE_REMOVABLE || type == DRIVE_USB) {
                count++;
            }
        }
    }
    return count;
}

MONITOR_API int block_autorun(const char* drive_letter) {
    if (!drive_letter) return 0;
    char autorun_path[MAX_PATH];
    sprintf_s(autorun_path, "%s\\autorun.inf", drive_letter);
    DWORD attr = GetFileAttributesA(autorun_path);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        char backup_path[MAX_PATH];
        sprintf_s(backup_path, "%s\\autorun.inf.shieldpro.bak", drive_letter);
        MoveFileA(autorun_path, backup_path);
        write_log(1, ("Blocked autorun.inf on " + std::string(drive_letter)).c_str());
        return 1;
    }
    return 0;
}

MONITOR_API int get_connected_drives(char* drives, int max_drives) {
    if (!drives || max_drives <= 0) return 0;
    DWORD mask = GetLogicalDrives();
    int idx = 0;
    for (int i = 0; i < 26 && idx < max_drives - 1; i++) {
        if (mask & (1 << i)) {
            char drive[4] = { 'A' + i, ':', '\\', '\0' };
            UINT type = GetDriveTypeA(drive);
            drives[idx++] = 'A' + i;
        }
    }
    drives[idx] = '\0';
    return idx;
}

MONITOR_API int register_autostart(const char* app_path, const char* reg_name) {
    if (!app_path || !reg_name) return 0;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        return 0;
    }
    RegSetValueExA(hKey, reg_name, 0, REG_SZ, (const BYTE*)app_path, (DWORD)strlen(app_path) + 1);
    RegCloseKey(hKey);
    write_log(1, ("Registered autostart: " + std::string(reg_name)).c_str());
    return 1;
}

MONITOR_API int unregister_autostart(const char* reg_name) {
    if (!reg_name) return 0;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        return 0;
    }
    RegDeleteValueA(hKey, reg_name);
    RegCloseKey(hKey);
    write_log(1, ("Unregistered autostart: " + std::string(reg_name)).c_str());
    return 1;
}

MONITOR_API int is_autostart_enabled(const char* reg_name) {
    if (!reg_name) return 0;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) {
        return 0;
    }
    char value[MAX_PATH];
    DWORD size = MAX_PATH;
    DWORD type;
    LONG result = RegQueryValueExA(hKey, reg_name, NULL, &type, (LPBYTE)value, &size);
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS) ? 1 : 0;
}

MONITOR_API void log_event(int level, const char* message) {
    write_log(level, message ? message : "null");
}

MONITOR_API const char* get_monitor_version(void) {
    return VERSION;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            InitializeCriticalSection(&g_cs);
            break;
        case DLL_PROCESS_DETACH:
            stop_monitor();
            DeleteCriticalSection(&g_cs);
            if (g_log_file) fclose(g_log_file);
            break;
    }
    return TRUE;
}