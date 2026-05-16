#pragma once

#ifndef SCAN_ENGINE_H
#define SCAN_ENGINE_H

#ifdef _WIN32
    #ifdef SCANENGINE_EXPORTS
        #define SCANENGINE_API __declspec(dllexport)
    #else
        #define SCANENGINE_API __declspec(dllimport)
    #endif
#else
    #define SCANENGINE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SIGNATURES 50000
#define MAX_SIGNATURE_NAME 256
#define MAX_PATH_LEN 1024
#define BUFFER_SIZE 131072

typedef struct {
    char name[MAX_SIGNATURE_NAME];
    unsigned char signature[512];
    int sig_length;
    int threat_type;
    int severity;
    char malware_family[64];
    char description[512];
} Signature;

typedef struct {
    char filepath[MAX_PATH_LEN];
    int is_infected;
    char threat_name[MAX_SIGNATURE_NAME];
    int threat_type;
    int severity;
    double confidence;
    unsigned long long file_size;
    char file_hash[65];
    char detection_time[32];
} ScanResult;

typedef struct {
    int total_files;
    int scanned_files;
    int infected_files;
    int cleaned_files;
    int quarantined_files;
    int errors;
    double progress;
    double scan_speed;
    unsigned long long bytes_scanned;
} ScanStatistics;

typedef struct {
    char scan_type[32];
    char root_path[MAX_PATH_LEN];
    int recursive;
    int max_depth;
    int follow_symlinks;
    int scan_archives;
    int scan_packed;
    int heuristic_enabled;
    int heuristic_level;
    unsigned long long max_file_size;
    int max_threads;
    char exclude_paths[4096];
} ScanConfiguration;

typedef void (*ScanProgressCallback)(int current, int total, const char* filepath, void* user_data);
typedef void (*ThreatFoundCallback)(ScanResult* result, void* user_data);

SCANENGINE_API int init_scan_engine(const char* db_path);
SCANENGINE_API void close_scan_engine();

SCANENGINE_API int load_signatures(const char* sig_file);
SCANENGINE_API int reload_signatures();
SCANENGINE_API int get_signature_count();

SCANENGINE_API int scan_file(const char* filepath, ScanResult* result);
SCANENGINE_API int scan_buffer(const unsigned char* buffer, int size, ScanResult* result);

SCANENGINE_API int scan_directory(const char* dir_path, ScanConfiguration* config,
                                   ScanProgressCallback progress_cb,
                                   ThreatFoundCallback threat_cb,
                                   void* user_data);

SCANENGINE_API int scan_directory_ex(const char* dir_path, ScanConfiguration* config,
                                      ScanStatistics* stats,
                                      ScanProgressCallback progress_cb,
                                      ThreatFoundCallback threat_cb,
                                      void* user_data);

SCANENGINE_API void stop_scan();
SCANENGINE_API int is_scanning();

SCANENGINE_API int get_scan_statistics(ScanStatistics* stats);

SCANENGINE_API int compute_file_hash(const char* filepath, char* hash_output, int hash_type);
SCANENGINE_API int verify_file_hash(const char* filepath, const char* expected_hash);

SCANENGINE_API int extract_archive(const char* archive_path, const char* dest_path, char* error, int error_size);
SCANENGINE_API int is_archive(const char* filepath);

SCANENGINE_API int add_custom_signature(const char* name, const unsigned char* sig, int sig_len, int threat_type);
SCANENGINE_API int remove_custom_signature(const char* name);
SCANENGINE_API int get_custom_signatures(Signature* sigs, int max_sigs);

SCANENGINE_API int enable_heuristic(int enable, int level);
SCANENGINE_API int set_scan_options(ScanConfiguration* config);
SCANENGINE_API int get_scan_options(ScanConfiguration* config);

SCANENGINE_API const char* get_engine_version();
SCANENGINE_API int get_engine_build();

SCANENGINE_API int scan_memory(int pid, ScanResult* results, int max_results);
SCANENGINE_API int scan_process(int pid, ScanResult* results, int max_results);

SCANENGINE_API int quarantine_file(const char* filepath, char* quarantine_path, int path_size);
SCANENGINE_API int restore_file(const char* quarantine_path, const char* original_path);
SCANENGINE_API int delete_file(const char* filepath);

SCANENGINE_API int add_exclusion_path(const char* path);
SCANENGINE_API int remove_exclusion_path(const char* path);
SCANENGINE_API int get_exclusion_paths(char* paths, int max_paths);

SCANENGINE_API int export_scan_report(const char* filepath, ScanStatistics* stats);

#ifdef __cplusplus
}
#endif

#endif