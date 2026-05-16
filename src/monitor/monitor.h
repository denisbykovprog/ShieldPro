#ifndef MONITOR_H
#define MONITOR_H

#ifdef _WIN32
#ifdef MONITOR_EXPORTS
#define MONITOR_API __declspec(dllexport)
#else
#define MONITOR_API __declspec(dllimport)
#endif
#else
#define MONITOR_API
#endif

#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char path[MAX_PATH];
    int event_type;
    int timestamp;
} FileEvent;

typedef void (*FileChangeCallback)(const char* path, int event_type, void* user_data);

typedef struct {
    char ip[64];
    int port;
    int direction;
    int action;
    int enabled;
} FirewallRule;

MONITOR_API int init_monitor(const char* watched_dirs[], int dir_count);
MONITOR_API void stop_monitor(void);
MONITOR_API int is_running(void);
MONITOR_API void set_file_callback(FileChangeCallback callback, void* user_data);

MONITOR_API int add_firewall_rule(const char* ip, int port, int direction, int action);
MONITOR_API int remove_firewall_rule(int rule_id);
MONITOR_API int get_firewall_rules(FirewallRule* rules, int max_rules);
MONITOR_API int get_firewall_rule_count(void);
MONITOR_API void clear_firewall_rules(void);

MONITOR_API int check_usb_devices(void);
MONITOR_API int block_autorun(const char* drive_letter);
MONITOR_API int get_connected_drives(char* drives, int max_drives);

MONITOR_API int register_autostart(const char* app_path, const char* reg_name);
MONITOR_API int unregister_autostart(const char* reg_name);
MONITOR_API int is_autostart_enabled(const char* reg_name);

MONITOR_API void log_event(int level, const char* message);
MONITOR_API const char* get_monitor_version(void);

#ifdef __cplusplus
}
#endif

#endif