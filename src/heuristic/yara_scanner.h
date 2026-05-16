#ifndef YARA_SCANNER_H
#define YARA_SCANNER_H

#ifdef _WIN32
    #ifdef YARA_EXPORTS
        #define YARA_API __declspec(dllexport)
    #else
        #define YARA_API __declspec(dllimport)
    #endif
#else
    #define YARA_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_YARA_RULES 5000
#define MAX_MATCHES 1000
#define MAX_RULE_NAME 256

typedef struct {
    char rule_name[MAX_RULE_NAME];
    char namespace_[128];
    int match_count;
    char* matched_strings;
    int matched_strings_size;
    double confidence;
    int severity;
} YaraMatch;

typedef struct {
    char* rules_data;
    int rules_count;
    int compiled;
    char error_message[1024];
} YaraRuleSet;

typedef struct {
    int total_matches;
    int high_confidence;
    int medium_confidence;
    int low_confidence;
    int rules_loaded;
} YaraScanStats;

YARA_API int init_yara_scanner(const char* rules_path);
YARA_API void close_yara_scanner();

YARA_API int load_yara_rules(const char* rules_file);
YARA_API int load_yara_rules_from_string(const char* rules_string);
YARA_API int reload_yara_rules();

YARA_API int scan_file_yara(const char* filepath, YaraMatch* matches, int max_matches);
YARA_API int scan_memory_yara(const unsigned char* buffer, int size, YaraMatch* matches, int max_matches);
YARA_API int scan_directory_yara(const char* dir_path, YaraScanStats* stats, int recursive);

YARA_API int get_yara_stats(YaraScanStats* stats);
YARA_API int get_rules_count();

YARA_API int add_custom_rule(const char* rule_name, const char* rule_definition);
YARA_API int remove_custom_rule(const char* rule_name);
YARA_API int list_custom_rules(char* rules, int max_size);

YARA_API int export_scan_results(const char* filepath, YaraMatch* matches, int match_count);
YARA_API int import_scan_results(const char* filepath, YaraMatch* matches, int* match_count);

YARA_API const char* get_yara_version();

#ifdef __cplusplus
}
#endif

#endif