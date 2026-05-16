#pragma once

#ifndef REALTIME_PROTECTION_H
#define REALTIME_PROTECTION_H

#ifdef _WIN32
    #ifdef RTPROT_EXPORTS
        #define RTPROT_API __declspec(dllexport)
    #else
        #define RTPROT_API __declspec(dllimport)
    #endif
#else
    #define RTPROT_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char file_path[MAX_PATH];
    int event_type;
    int timestamp;
    int blocked;
    char threat_name[256];
} FileSystemEvent;

typedef struct {
    char process_name[260];
    unsigned long pid;
    char action[128];
    int allowed;
    int timestamp;
} ProcessEvent;

typedef struct {
    char url[2048];
    char domain[512];
    int port;
    int protocol;
    int blocked;
    char reason[512];
} NetworkEvent;

typedef void (*FileEventCallback)(FileSystemEvent* event, void* user_data);
typedef void (*ProcessEventCallback)(ProcessEvent* event, void* user_data);
typedef void (*NetworkEventCallback)(NetworkEvent* event, void* user_data);

RTPROT_API int init_realtime_protection();
RTPROT_API void shutdown_realtime_protection();

RTPROT_API int start_protection();
RTPROT_API int stop_protection();
RTPROT_API int is_protection_active();

RTPROT_API int add_watch_directory(const char* path, int recursive);
RTPROT_API int remove_watch_directory(const char* path);
RTPROT_API int get_watch_directories(char* paths, int max_paths);

RTPROT_API int set_file_callback(FileEventCallback callback, void* user_data);
RTPROT_API int set_process_callback(ProcessEventCallback callback, void* user_data);
RTPROT_API int set_network_callback(NetworkEventCallback callback, void* user_data);

RTPROT_API int enable_file_protection(int enable);
RTPROT_API int enable_process_protection(int enable);
RTPROT_API int enable_network_protection(int enable);

RTPROT_API int add_file_rule(const char* pattern, int action);
RTPROT_API int add_process_rule(const char* process_name, int action);
RTPROT_API int add_network_rule(const char* domain, int port, int action);

RTPROT_API int get_protection_stats(int* files_scanned, int* threats_blocked, int* events_logged);

RTPROT_API int scan_file_on_access(const char* filepath);
RTPROT_API int quarantine_on_detection(int enable);

RTPROT_API int enable_boot_protection(int enable);
RTPROT_API int enable_registry_protection(int enable);

RTPROT_API int get_blocked_files_count();
RTPROT_API int get_blocked_processes_count();
RTPROT_API int get_blocked_connections_count();

RTPROT_API int clear_protection_logs();
RTPROT_API int export_protection_logs(const char* filepath);

RTPROT_API const char* get_realtime_version();

#ifdef __cplusplus
}
#endif

#endif