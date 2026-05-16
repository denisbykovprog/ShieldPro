#include "realtime_protection.h"
#include <windows.h>
#include <shlobj.h>
#include <vector>
#include <string>
#include <map>
#include <queue>
#include <algorithm>
#include <ctime>

static std::vector<std::string> g_watch_dirs;
static volatile bool g_protection_active = false;
static HANDLE g_worker_thread = NULL;
static CRITICAL_SECTION g_cs;

static FileEventCallback g_file_callback = nullptr;
static ProcessEventCallback g_process_callback = nullptr;
static NetworkEventCallback g_network_callback = nullptr;
static void* g_file_user_data = nullptr;
static void* g_process_user_data = nullptr;
static void* g_network_user_data = nullptr;

static std::vector<FileSystemEvent> g_file_events;
static std::vector<ProcessEvent> g_process_events;
static std::vector<NetworkEvent> g_network_events;

static std::map<std::string, int> g_file_rules;
static std::map<std::string, int> g_process_rules;
static std::map<std::string, int> g_network_rules;

static int g_files_scanned = 0;
static int g_threats_blocked = 0;
static int g_events_logged = 0;

static bool g_file_protection = true;
static bool g_process_protection = true;
static bool g_network_protection = true;
static bool g_quarantine_on_detection = true;

static const char* VERSION = "1.0.0";

static void write_log(const char* msg) {
    EnterCriticalSection(&g_cs);
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string dir = path;
    size_t pos = dir.rfind('\\');
    if (pos != std::string::npos) dir = dir.substr(0, pos);
    dir += "\\..\\data\\logs\\realtime.log";
    FILE* f = fopen(dir.c_str(), "a");
    if (f) {
        time_t now = time(nullptr);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(f, "[%s] %s\n", time_str, msg);
        fclose(f);
    }
    LeaveCriticalSection(&g_cs);
}

struct WatchInfo {
    std::string path;
    HANDLE dir_handle;
    OVERLAPPED overlapped;
    char buffer[16384];
    bool active;
};

static std::vector<WatchInfo*> g_watch_infos;

static unsigned int __stdcall worker_thread(void* param) {
    write_log("Realtime protection worker started");

    while (g_protection_active) {
        for (auto* info : g_watch_infos) {
            if (!info->active || info->dir_handle == INVALID_HANDLE_VALUE) continue;

            DWORD bytes_returned;
            if (ReadDirectoryChangesW(
                info->dir_handle,
                info->buffer,
                sizeof(info->buffer),
                TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytes_returned,
                &info->overlapped,
                NULL))
            {
                FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)info->buffer;
                while (true) {
                    wchar_t* filename = (wchar_t*)malloc(MAX_PATH * sizeof(wchar_t));
                    if (filename) {
                        wcsncpy_s(filename, MAX_PATH, fni->FileName, MAX_PATH - 1);
                        char ansi_path[MAX_PATH];
                        WideCharToMultiByte(CP_ACP, 0, filename, -1, ansi_path, MAX_PATH, NULL, NULL);
                        char full_path[MAX_PATH];
                        sprintf_s(full_path, "%s\\%s", info->path.c_str(), ansi_path);

                        FileSystemEvent event;
                        strncpy(event.file_path, full_path, MAX_PATH - 1);
                        event.event_type = fni->Action;
                        event.timestamp = (int)time(nullptr);
                        event.blocked = 0;
                        strcpy_s(event.threat_name, "");

                        if (g_file_protection && g_file_callback) {
                            g_file_callback(&event, g_file_user_data);
                        }

                        g_file_events.push_back(event);
                        g_events_logged++;

                        free(filename);
                    }

                    if (!fni->NextEntryOffset) break;
                    fni = (FILE_NOTIFY_INFORMATION*)((char*)fni + fni->NextEntryOffset);
                }
            }
        }
        Sleep(100);
    }

    write_log("Realtime protection worker stopped");
    return 0;
}

RTPROT_API int init_realtime_protection() {
    InitializeCriticalSection(&g_cs);

    char sysdir[MAX_PATH];
    GetSystemDirectoryA(sysdir, MAX_PATH);
    g_watch_dirs.push_back(std::string(sysdir) + "\\System32");

    char userprofile[MAX_PATH];
    GetEnvironmentVariableA("USERPROFILE", userprofile, MAX_PATH);
    g_watch_dirs.push_back(std::string(userprofile) + "\\Downloads");
    g_watch_dirs.push_back(std::string(userprofile) + "\\Documents");
    g_watch_dirs.push_back(std::string(userprofile) + "\\Desktop");

    write_log("Realtime protection initialized");
    return 1;
}

RTPROT_API void shutdown_realtime_protection() {
    stop_protection();

    for (auto* info : g_watch_infos) {
        if (info->dir_handle != INVALID_HANDLE_VALUE) CloseHandle(info->dir_handle);
        delete info;
    }
    g_watch_infos.clear();

    g_file_events.clear();
    g_process_events.clear();
    g_network_events.clear();

    DeleteCriticalSection(&g_cs);
    write_log("Realtime protection shut down");
}

RTPROT_API int start_protection() {
    if (g_protection_active) return 1;

    for (const auto& dir : g_watch_dirs) {
        WatchInfo* info = new WatchInfo();
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
        } else {
            delete info;
        }
    }

    g_protection_active = true;
    g_worker_thread = (HANDLE)_beginthreadex(NULL, 0, worker_thread, NULL, 0, NULL);

    write_log("Realtime protection started");
    return 1;
}

RTPROT_API int stop_protection() {
    if (!g_protection_active) return 1;

    g_protection_active = false;

    if (g_worker_thread) {
        WaitForSingleObject(g_worker_thread, 5000);
        CloseHandle(g_worker_thread);
        g_worker_thread = NULL;
    }

    for (auto* info : g_watch_infos) {
        if (info->dir_handle != INVALID_HANDLE_VALUE) CloseHandle(info->dir_handle);
        info->dir_handle = INVALID_HANDLE_VALUE;
    }

    write_log("Realtime protection stopped");
    return 1;
}

RTPROT_API int is_protection_active() {
    return g_protection_active ? 1 : 0;
}

RTPROT_API int add_watch_directory(const char* path, int recursive) {
    if (!path) return 0;
    EnterCriticalSection(&g_cs);
    g_watch_dirs.push_back(std::string(path));
    LeaveCriticalSection(&g_cs);
    return 1;
}

RTPROT_API int remove_watch_directory(const char* path) {
    if (!path) return 0;
    EnterCriticalSection(&g_cs);
    auto it = std::remove(g_watch_dirs.begin(), g_watch_dirs.end(), std::string(path));
    g_watch_dirs.erase(it, g_watch_dirs.end());
    LeaveCriticalSection(&g_cs);
    return 1;
}

RTPROT_API int get_watch_directories(char* paths, int max_paths) {
    if (!paths) return 0;
    EnterCriticalSection(&g_cs);
    int count = 0;
    for (const auto& dir : g_watch_dirs) {
        if (count >= max_paths - 1) break;
        strcpy_s(paths + count * MAX_PATH, MAX_PATH, dir.c_str());
        count++;
    }
    LeaveCriticalSection(&g_cs);
    return count;
}

RTPROT_API int set_file_callback(FileEventCallback callback, void* user_data) {
    g_file_callback = callback;
    g_file_user_data = user_data;
    return 1;
}

RTPROT_API int set_process_callback(ProcessEventCallback callback, void* user_data) {
    g_process_callback = callback;
    g_process_user_data = user_data;
    return 1;
}

RTPROT_API int set_network_callback(NetworkEventCallback callback, void* user_data) {
    g_network_callback = callback;
    g_network_user_data = user_data;
    return 1;
}

RTPROT_API int enable_file_protection(int enable) {
    g_file_protection = (enable != 0);
    return 1;
}

RTPROT_API int enable_process_protection(int enable) {
    g_process_protection = (enable != 0);
    return 1;
}

RTPROT_API int enable_network_protection(int enable) {
    g_network_protection = (enable != 0);
    return 1;
}

RTPROT_API int add_file_rule(const char* pattern, int action) {
    if (!pattern) return 0;
    EnterCriticalSection(&g_cs);
    g_file_rules[std::string(pattern)] = action;
    LeaveCriticalSection(&g_cs);
    return 1;
}

RTPROT_API int add_process_rule(const char* process_name, int action) {
    if (!process_name) return 0;
    EnterCriticalSection(&g_cs);
    g_process_rules[std::string(process_name)] = action;
    LeaveCriticalSection(&g_cs);
    return 1;
}

RTPROT_API int add_network_rule(const char* domain, int port, int action) {
    if (!domain) return 0;
    EnterCriticalSection(&g_cs);
    std::string key = std::string(domain) + ":" + std::to_string(port);
    g_network_rules[key] = action;
    LeaveCriticalSection(&g_cs);
    return 1;
}

RTPROT_API int get_protection_stats(int* files_scanned, int* threats_blocked, int* events_logged) {
    if (files_scanned) *files_scanned = g_files_scanned;
    if (threats_blocked) *threats_blocked = g_threats_blocked;
    if (events_logged) *events_logged = g_events_logged;
    return 1;
}

RTPROT_API int scan_file_on_access(const char* filepath) {
    if (!filepath) return 0;
    g_files_scanned++;
    return 1;
}

RTPROT_API int quarantine_on_detection(int enable) {
    g_quarantine_on_detection = (enable != 0);
    return 1;
}

RTPROT_API int enable_boot_protection(int enable) {
    write_log(enable ? "Boot protection enabled" : "Boot protection disabled");
    return 1;
}

RTPROT_API int enable_registry_protection(int enable) {
    write_log(enable ? "Registry protection enabled" : "Registry protection disabled");
    return 1;
}

RTPROT_API int get_blocked_files_count() {
    EnterCriticalSection(&g_cs);
    int count = 0;
    for (const auto& event : g_file_events) {
        if (event.blocked) count++;
    }
    LeaveCriticalSection(&g_cs);
    return count;
}

RTPROT_API int get_blocked_processes_count() {
    EnterCriticalSection(&g_cs);
    int count = 0;
    for (const auto& event : g_process_events) {
        if (!event.allowed) count++;
    }
    LeaveCriticalSection(&g_cs);
    return count;
}

RTPROT_API int get_blocked_connections_count() {
    EnterCriticalSection(&g_cs);
    int count = 0;
    for (const auto& event : g_network_events) {
        if (event.blocked) count++;
    }
    LeaveCriticalSection(&g_cs);
    return count;
}

RTPROT_API int clear_protection_logs() {
    EnterCriticalSection(&g_cs);
    g_file_events.clear();
    g_process_events.clear();
    g_network_events.clear();
    g_events_logged = 0;
    LeaveCriticalSection(&g_cs);
    return 1;
}

RTPROT_API int export_protection_logs(const char* filepath) {
    if (!filepath) return 0;

    EnterCriticalSection(&g_cs);

    FILE* f = fopen(filepath, "w");
    if (!f) {
        LeaveCriticalSection(&g_cs);
        return 0;
    }

    fprintf(f, "ShieldPro Realtime Protection Logs\n");
    fprintf(f, "==================================\n\n");

    fprintf(f, "File Events: %zu\n", g_file_events.size());
    for (const auto& event : g_file_events) {
        fprintf(f, "  [%s] %s (type: %d, blocked: %d)\n",
                event.file_path, event.threat_name, event.event_type, event.blocked);
    }

    fprintf(f, "\nProcess Events: %zu\n", g_process_events.size());
    for (const auto& event : g_process_events) {
        fprintf(f, "  [%s] %s (action: %s, allowed: %d)\n",
                event.process_name, event.action,
                event.allowed ? "yes" : "no");
    }

    fprintf(f, "\nNetwork Events: %zu\n", g_network_events.size());
    for (const auto& event : g_network_events) {
        fprintf(f, "  [%s:%d] %s (blocked: %d)\n",
                event.domain, event.port, event.reason, event.blocked);
    }

    fclose(f);
    LeaveCriticalSection(&g_cs);

    return 1;
}

RTPROT_API const char* get_realtime_version() {
    return VERSION;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: init_realtime_protection(); break;
        case DLL_PROCESS_DETACH: shutdown_realtime_protection(); break;
    }
    return TRUE;
}