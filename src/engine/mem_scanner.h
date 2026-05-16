#ifndef MEMORY_SCANNER_H
#define MEMORY_SCANNER_H

#ifdef _WIN32
    #ifdef MEMSCAN_EXPORTS
        #define MEMSCAN_API __declspec(dllexport)
    #else
        #define MEMSCAN_API __declspec(dllimport)
    #endif
#else
    #define MEMSCAN_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned long pid;
    char process_name[260];
    unsigned long long working_set;
    unsigned long long private_bytes;
    int thread_count;
    int module_count;
    int is_suspicious;
    double threat_score;
} ProcessInfo;

typedef struct {
    unsigned long base_address;
    unsigned long size;
    char section_name[10];
    unsigned long entropy;
    int is_executable;
    int is_writable;
    int is_copy_on_write;
} MemoryRegion;

typedef struct {
    unsigned long pid;
    unsigned long address;
    unsigned long size;
    char content[256];
    int is_injected;
    int is_hidden;
    int threat_score;
} MemoryThreat;

MEMSCAN_API int init_memory_scanner();
MEMSCAN_API void close_memory_scanner();

MEMSCAN_API int enumerate_processes(ProcessInfo* processes, int max_count);
MEMSCAN_API int get_process_info(unsigned long pid, ProcessInfo* info);

MEMSCAN_API int scan_process_memory(unsigned long pid, MemoryThreat* threats, int max_threats);
MEMSCAN_API int scan_all_processes(MemoryThreat* threats, int max_threats, int* scanned_processes);

MEMSCAN_API int get_memory_regions(unsigned long pid, MemoryRegion* regions, int max_regions);

MEMSCAN_API int detect_injected_dlls(unsigned long pid, char* dll_paths, int max_paths);
MEMSCAN_API int detect_shellcode(unsigned long pid, MemoryThreat* threats, int max_threats);

MEMSCAN_API int suspend_process(unsigned long pid);
MEMSCAN_API int resume_process(unsigned long pid);

MEMSCAN_API int terminate_process(unsigned long pid, int force);

MEMSCAN_API int create_process_dump(unsigned long pid, const char* dump_path);

MEMSCAN_API const char* get_scanner_version();

#ifdef __cplusplus
}
#endif

#endif