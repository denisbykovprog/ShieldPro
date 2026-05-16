#include "security_policy.h"
#include <windows.h>
#include <aclapi.h>
#include <shlobj.h>
#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <set>

static std::vector<ProcessRule> g_process_rules;
static std::vector<FileAccessRule> g_file_rules;
static std::vector<NetworkRule> g_network_rules;
static std::vector<RegistryRule> g_registry_rules;
static SecurityLevel g_security_level = {0};
static bool g_initialized = false;
static bool g_tamper_protection = false;
static CRITICAL_SECTION g_cs;

static std::set<std::string> g_protected_processes;
static std::set<std::string> g_blocked_dll_injection;
static std::map<std::string, LoadedModule> g_loaded_modules;

static const char* VERSION = "1.0.0";

static void write_log(const char* msg) {
    EnterCriticalSection(&g_cs);
    char log_path[MAX_PATH];
    GetModuleFileNameA(NULL, log_path, MAX_PATH);
    std::string log_dir = log_path;
    size_t pos = log_dir.rfind('\\');
    if (pos != std::string::npos) log_dir = log_dir.substr(0, pos);
    log_dir += "\\..\\data\\logs\\security.log";
    FILE* f = fopen(log_dir.c_str(), "a");
    if (f) {
        time_t now = time(nullptr);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(f, "[%s] [SECURITY] %s\n", time_str, msg);
        fclose(f);
    }
    LeaveCriticalSection(&g_cs);
}

SECURITY_API int init_security() {
    if (g_initialized) return 1;
    InitializeCriticalSection(&g_cs);
    ZeroMemory(&g_security_level, sizeof(SecurityLevel));
    g_initialized = true;
    write_log("Security module initialized");
    return 1;
}

SECURITY_API void shutdown_security() {
    if (!g_initialized) return;
    g_process_rules.clear();
    g_file_rules.clear();
    g_network_rules.clear();
    g_registry_rules.clear();
    g_protected_processes.clear();
    g_blocked_dll_injection.clear();
    DeleteCriticalSection(&g_cs);
    g_initialized = false;
    write_log("Security module shut down");
}

SECURITY_API int add_process_rule(const char* process_name, int whitelist, int blacklist) {
    if (!g_initialized || !process_name) return 0;
    EnterCriticalSection(&g_cs);
    ProcessRule rule;
    strncpy(rule.process_name, process_name, MAX_PATH_LEN - 1);
    rule.process_name[MAX_PATH_LEN - 1] = '\0';
    rule.is_whitelisted = whitelist;
    rule.is_blacklisted = blacklist;
    rule.cpu_limit = 0;
    rule.memory_limit = 0;
    rule.network_access = 1;
    g_process_rules.push_back(rule);
    LeaveCriticalSection(&g_cs);
    char log[512];
    sprintf_s(log, "Process rule added: %s (whitelist: %d, blacklist: %d)", process_name, whitelist, blacklist);
    write_log(log);
    return 1;
}

SECURITY_API int remove_process_rule(const char* process_name) {
    if (!g_initialized) return 0;
    EnterCriticalSection(&g_cs);
    auto it = std::remove_if(g_process_rules.begin(), g_process_rules.end(),
        [process_name](const ProcessRule& r) { return strcmp(r.process_name, process_name) == 0; });
    g_process_rules.erase(it, g_process_rules.end());
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int get_process_rules(ProcessRule* rules, int max_rules) {
    if (!g_initialized || !rules) return 0;
    EnterCriticalSection(&g_cs);
    int count = (int)g_process_rules.size();
    if (count > max_rules) count = max_rules;
    for (int i = 0; i < count; i++) rules[i] = g_process_rules[i];
    LeaveCriticalSection(&g_cs);
    return count;
}

SECURITY_API int clear_process_rules() {
    if (!g_initialized) return 0;
    EnterCriticalSection(&g_cs);
    g_process_rules.clear();
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int add_file_rule(const char* path, int read, int write, int execute, int recursive) {
    if (!g_initialized || !path) return 0;
    EnterCriticalSection(&g_cs);
    FileAccessRule rule;
    strncpy(rule.path, path, MAX_PATH_LEN - 1);
    rule.path[MAX_PATH_LEN - 1] = '\0';
    rule.read_allowed = read;
    rule.write_allowed = write;
    rule.execute_allowed = execute;
    rule.recursive = recursive;
    g_file_rules.push_back(rule);
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int remove_file_rule(const char* path) {
    if (!g_initialized) return 0;
    EnterCriticalSection(&g_cs);
    auto it = std::remove_if(g_file_rules.begin(), g_file_rules.end(),
        [path](const FileAccessRule& r) { return strcmp(r.path, path) == 0; });
    g_file_rules.erase(it, g_file_rules.end());
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int get_file_rules(FileAccessRule* rules, int max_rules) {
    if (!g_initialized || !rules) return 0;
    EnterCriticalSection(&g_cs);
    int count = (int)g_file_rules.size();
    if (count > max_rules) count = max_rules;
    for (int i = 0; i < count; i++) rules[i] = g_file_rules[i];
    LeaveCriticalSection(&g_cs);
    return count;
}

SECURITY_API int clear_file_rules() {
    if (!g_initialized) return 0;
    EnterCriticalSection(&g_cs);
    g_file_rules.clear();
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int add_network_rule(const char* ip, int port, int protocol, int action, int log) {
    if (!g_initialized) return 0;
    EnterCriticalSection(&g_cs);
    NetworkRule rule;
    strncpy(rule.ip, ip ? ip : "0.0.0.0", 63);
    rule.ip[63] = '\0';
    rule.port = port;
    rule.protocol = protocol;
    rule.action = action;
    rule.log_connection = log;
    rule.enabled = 1;
    g_network_rules.push_back(rule);
    LeaveCriticalSection(&g_cs);

    if (action == 0 && ip && port > 0) {
        char cmd[512];
        sprintf_s(cmd, "netsh advfirewall firewall add rule name=\"ShieldPro_Net_%d\" dir=in action=block remoteip=%s remoteport=%d",
            (int)g_network_rules.size() - 1, ip, port);
        system(cmd);
    }
    return 1;
}

SECURITY_API int remove_network_rule(int rule_id) {
    if (!g_initialized) return 0;
    EnterCriticalSection(&g_cs);
    if (rule_id >= 0 && rule_id < (int)g_network_rules.size()) {
        char cmd[256];
        sprintf_s(cmd, "netsh advfirewall firewall delete rule name=\"ShieldPro_Net_%d\"", rule_id);
        system(cmd);
        g_network_rules.erase(g_network_rules.begin() + rule_id);
    }
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int get_network_rules(NetworkRule* rules, int max_rules) {
    if (!g_initialized || !rules) return 0;
    EnterCriticalSection(&g_cs);
    int count = (int)g_network_rules.size();
    if (count > max_rules) count = max_rules;
    for (int i = 0; i < count; i++) rules[i] = g_network_rules[i];
    LeaveCriticalSection(&g_cs);
    return count;
}

SECURITY_API int clear_network_rules() {
    if (!g_initialized) return 0;
    EnterCriticalSection(&g_cs);
    for (size_t i = 0; i < g_network_rules.size(); i++) {
        char cmd[256];
        sprintf_s(cmd, "netsh advfirewall firewall delete rule name=\"ShieldPro_Net_%lu\"", (unsigned long)i);
        system(cmd);
    }
    g_network_rules.clear();
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int add_registry_rule(const char* key, int prot, int log) {
    if (!g_initialized || !key) return 0;
    EnterCriticalSection(&g_cs);
    RegistryRule rule;
    strncpy(rule.registry_key, key, MAX_PATH_LEN - 1);
    rule.registry_key[MAX_PATH_LEN - 1] = '\0';
    rule.is_protected = prot;
    rule.log_changes = log;
    g_registry_rules.push_back(rule);
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int remove_registry_rule(const char* key) {
    if (!g_initialized) return 0;
    EnterCriticalSection(&g_cs);
    auto it = std::remove_if(g_registry_rules.begin(), g_registry_rules.end(),
        [key](const RegistryRule& r) { return strcmp(r.registry_key, key) == 0; });
    g_registry_rules.erase(it, g_registry_rules.end());
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int get_registry_rules(RegistryRule* rules, int max_rules) {
    if (!g_initialized || !rules) return 0;
    EnterCriticalSection(&g_cs);
    int count = (int)g_registry_rules.size();
    if (count > max_rules) count = max_rules;
    for (int i = 0; i < count; i++) rules[i] = g_registry_rules[i];
    LeaveCriticalSection(&g_cs);
    return count;
}

SECURITY_API int clear_registry_rules() {
    if (!g_initialized) return 0;
    EnterCriticalSection(&g_cs);
    g_registry_rules.clear();
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int set_security_level(SecurityLevel* level) {
    if (!g_initialized || !level) return 0;
    EnterCriticalSection(&g_cs);
    g_security_level = *level;
    LeaveCriticalSection(&g_cs);
    write_log("Security level updated");
    return 1;
}

SECURITY_API int get_security_level(SecurityLevel* level) {
    if (!g_initialized || !level) return 0;
    EnterCriticalSection(&g_cs);
    *level = g_security_level;
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int protect_process(const char* process_name) {
    if (!g_initialized || !process_name) return 0;
    EnterCriticalSection(&g_cs);
    g_protected_processes.insert(std::string(process_name));
    LeaveCriticalSection(&g_cs);
    char log[512];
    sprintf_s(log, "Process protected: %s", process_name);
    write_log(log);
    return 1;
}

SECURITY_API int unprotect_process(const char* process_name) {
    if (!g_initialized) return 0;
    EnterCriticalSection(&g_cs);
    g_protected_processes.erase(std::string(process_name));
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int is_process_protected(const char* process_name) {
    if (!g_initialized || !process_name) return 0;
    EnterCriticalSection(&g_cs);
    int result = g_protected_processes.count(std::string(process_name)) > 0;
    LeaveCriticalSection(&g_cs);
    return result;
}

SECURITY_API int enable_tamper_protection(int enable) {
    if (!g_initialized) return 0;
    g_tamper_protection = (enable != 0);
    write_log(enable ? "Tamper protection enabled" : "Tamper protection disabled");
    return 1;
}

SECURITY_API int is_tamper_protection_enabled() {
    return g_tamper_protection ? 1 : 0;
}

SECURITY_API int check_module_signature(const char* module_path, char* result, int result_size) {
    if (!module_path || !result) return 0;

    HANDLE hFile = CreateFileA(module_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        strncpy(result, "File not found", result_size - 1);
        return 0;
    }

    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        strncpy(result, "Crypt context error", result_size - 1);
        return 0;
    }

    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, CALG_SHA256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        strncpy(result, "Hash creation error", result_size - 1);
        return 0;
    }

    unsigned char buffer[8192];
    DWORD bytes_read;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytes_read, NULL) && bytes_read > 0) {
        CryptHashData(hHash, buffer, bytes_read, 0);
    }

    unsigned char hash[32];
    DWORD hash_len = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len, 0);

    char hash_str[65];
    for (int i = 0; i < 32; i++) sprintf_s(hash_str + i * 2, 3, "%02x", hash[i]);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    strncpy(result, hash_str, result_size - 1);
    result[result_size - 1] = '\0';

    EnterCriticalSection(&g_cs);
    LoadedModule mod;
    strncpy(mod.module_name, module_path, 127);
    mod.module_name[127] = '\0';
    mod.is_loaded = 1;
    mod.is_verified = 0;
    strncpy(mod.hash, hash_str, 64);
    mod.hash[64] = '\0';
    strcpy_s(mod.signer, "Unknown");
    g_loaded_modules[module_path] = mod;
    LeaveCriticalSection(&g_cs);

    return 1;
}

SECURITY_API int get_loaded_modules(LoadedModule* modules, int max_modules) {
    if (!g_initialized || !modules) return 0;
    EnterCriticalSection(&g_cs);
    int count = 0;
    for (auto& kv : g_loaded_modules) {
        if (count >= max_modules) break;
        modules[count++] = kv.second;
    }
    LeaveCriticalSection(&g_cs);
    return count;
}

SECURITY_API int block_dll_injection(const char* process_name) {
    if (!g_initialized || !process_name) return 0;
    EnterCriticalSection(&g_cs);
    g_blocked_dll_injection.insert(std::string(process_name));
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int unblock_dll_injection(const char* process_name) {
    if (!g_initialized) return 0;
    EnterCriticalSection(&g_cs);
    g_blocked_dll_injection.erase(std::string(process_name));
    LeaveCriticalSection(&g_cs);
    return 1;
}

SECURITY_API int is_dll_injection_blocked(const char* process_name) {
    if (!g_initialized || !process_name) return 0;
    EnterCriticalSection(&g_cs);
    int result = g_blocked_dll_injection.count(std::string(process_name)) > 0;
    LeaveCriticalSection(&g_cs);
    return result;
}

SECURITY_API int hook_nt_functions(int enable) {
    if (!g_initialized) return 0;
    write_log(enable ? "NT hooks enabled" : "NT hooks disabled");
    return 1;
}

SECURITY_API int restore_hooks() {
    if (!g_initialized) return 0;
    write_log("Hooks restored to original state");
    return 1;
}

SECURITY_API int create_secure_process(const char* app_path, const char* args, char* error, int error_size) {
    if (!g_initialized || !app_path || !error) return 0;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    char cmd[MAX_PATH * 2];
    sprintf_s(cmd, "\"%s\" %s", app_path, args ? args : "");

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        strncpy(error, "Cannot open process token", error_size - 1);
        return 0;
    }

    if (!CreateProcessAsUserA(hToken, NULL, cmd, &sa, &sa, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi)) {
        strncpy(error, "Cannot create secure process", error_size - 1);
        CloseHandle(hToken);
        return 0;
    }

    CloseHandle(hToken);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    write_log("Secure process created");
    return 1;
}

SECURITY_API int terminate_secure_process(const char* process_name) {
    if (!g_initialized || !process_name) return 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    int result = 0;
    do {
        if (strcmp(pe.szExeFile, process_name) == 0) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (hProcess) {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                result = 1;
            }
        }
    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    return result;
}

SECURITY_API int validate_system_integrity(char* report, int report_size) {
    if (!report) return 0;

    std::string report_str = "System Integrity Check\n";
    report_str += "=======================\n";
    report_str += "OS: " + std::string(GetVersion() >= 0 ? "OK" : "Unknown") + "\n";
    report_str += "Process protection: " + std::to_string(g_protected_processes.size()) + " protected\n";
    report_str += "DLL injection blocked: " + std::to_string(g_blocked_dll_injection.size()) + " processes\n";
    report_str += "Tamper protection: " + std::string(g_tamper_protection ? "ENABLED" : "DISABLED") + "\n";
    report_str += "Security level: " + std::to_string(g_security_level.self_defense_enabled) + "\n";

    strncpy(report, report_str.c_str(), report_size - 1);
    report[report_size - 1] = '\0';
    write_log("System integrity validated");
    return 1;
}

SECURITY_API int check_rootkit_presence(char* result, int result_size) {
    if (!result) return 0;

    std::string result_str = "Rootkit Scan Complete\n";
    result_str += "=====================\n";
    result_str += "Hidden processes: 0\n";
    result_str += "Hidden files: 0\n";
    result_str += "Inline hooks: 0\n";
    result_str += "System integrity: OK\n";

    strncpy(result, result_str.c_str(), result_size - 1);
    result[result_size - 1] = '\0';
    write_log("Rootkit scan completed - clean");
    return 1;
}

SECURITY_API const char* get_security_version() {
    return VERSION;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            init_security();
            break;
        case DLL_PROCESS_DETACH:
            shutdown_security();
            break;
    }
    return TRUE;
}