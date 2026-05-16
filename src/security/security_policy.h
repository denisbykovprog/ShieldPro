#pragma once

#ifndef SECURITY_POLICY_H
#define SECURITY_POLICY_H

#ifdef _WIN32
    #ifdef SECURITY_API_EXPORTS
        #define SECURITY_API __declspec(dllexport)
    #else
        #define SECURITY_API __declspec(dllimport)
    #endif
#else
    #define SECURITY_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PROCESSES 1024
#define MAX_RULES 512
#define MAX_PATH_LEN 1024

typedef struct {
    char process_name[MAX_PATH_LEN];
    int is_whitelisted;
    int is_blacklisted;
    int cpu_limit;
    int memory_limit;
    int network_access;
} ProcessRule;

typedef struct {
    char path[MAX_PATH_LEN];
    int read_allowed;
    int write_allowed;
    int execute_allowed;
    int recursive;
} FileAccessRule;

typedef struct {
    char ip[64];
    int port;
    int protocol;
    int action;
    int log_connection;
    int enabled;
} NetworkRule;

typedef struct {
    char registry_key[MAX_PATH_LEN];
    int is_protected;
    int log_changes;
} RegistryRule;

typedef struct {
    int self_defense_enabled;
    int tamper_protection;
    int process_protection;
    int service_protection;
    int driver_protection;
    int boot_protection;
} SecurityLevel;

typedef struct {
    char module_name[128];
    int is_loaded;
    int is_verified;
    char hash[65];
    char signer[256];
} LoadedModule;

SECURITY_API int init_security();
SECURITY_API void shutdown_security();

SECURITY_API int add_process_rule(const char* process_name, int whitelist, int blacklist);
SECURITY_API int remove_process_rule(const char* process_name);
SECURITY_API int get_process_rules(ProcessRule* rules, int max_rules);
SECURITY_API int clear_process_rules();

SECURITY_API int add_file_rule(const char* path, int read, int write, int execute, int recursive);
SECURITY_API int remove_file_rule(const char* path);
SECURITY_API int get_file_rules(FileAccessRule* rules, int max_rules);
SECURITY_API int clear_file_rules();

SECURITY_API int add_network_rule(const char* ip, int port, int protocol, int action, int log);
SECURITY_API int remove_network_rule(int rule_id);
SECURITY_API int get_network_rules(NetworkRule* rules, int max_rules);
SECURITY_API int clear_network_rules();

SECURITY_API int add_registry_rule(const char* key, int protected, int log);
SECURITY_API int remove_registry_rule(const char* key);
SECURITY_API int get_registry_rules(RegistryRule* rules, int max_rules);
SECURITY_API int clear_registry_rules();

SECURITY_API int set_security_level(SecurityLevel* level);
SECURITY_API int get_security_level(SecurityLevel* level);

SECURITY_API int protect_process(const char* process_name);
SECURITY_API int unprotect_process(const char* process_name);
SECURITY_API int is_process_protected(const char* process_name);

SECURITY_API int enable_tamper_protection(int enable);
SECURITY_API int is_tamper_protection_enabled();

SECURITY_API int check_module_signature(const char* module_path, char* result, int result_size);
SECURITY_API int get_loaded_modules(LoadedModule* modules, int max_modules);

SECURITY_API int block_dll_injection(const char* process_name);
SECURITY_API int unblock_dll_injection(const char* process_name);
SECURITY_API int is_dll_injection_blocked(const char* process_name);

SECURITY_API int hook_nt_functions(int enable);
SECURITY_API int restore_hooks();

SECURITY_API int create_secure_process(const char* app_path, const char* args, char* error, int error_size);
SECURITY_API int terminate_secure_process(const char* process_name);

SECURITY_API int validate_system_integrity(char* report, int report_size);
SECURITY_API int check_rootkit_presence(char* result, int result_size);

SECURITY_API const char* get_security_version();

#ifdef __cplusplus
}
#endif

#endif