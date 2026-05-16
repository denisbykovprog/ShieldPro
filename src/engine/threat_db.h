#pragma once

#ifndef THREAT_DB_H
#define THREAT_DB_H

#ifdef _WIN32
    #ifdef THREATDB_EXPORTS
        #define THREATDB_API __declspec(dllexport)
    #else
        #define THREATDB_API __declspec(dllimport)
    #endif
#else
    #define THREATDB_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char malware_id[64];
    char name[128];
    char type[64];
    char family[128];
    int severity;
    char description[1024];
    char remediation[512];
    char created_date[32];
    char modified_date[32];
} ThreatEntry;

typedef struct {
    int threat_count;
    int families_count;
    int last_update;
    char version[32];
} ThreatDatabaseInfo;

THREATDB_API int init_threat_db(const char* db_path);
THREATDB_API void close_threat_db();

THREATDB_API int load_threat_database(const char* db_file);
THREATDB_API int save_threat_database(const char* db_file);

THREATDB_API int add_threat(ThreatEntry* entry);
THREATDB_API int update_threat(const char* malware_id, ThreatEntry* entry);
THREATDB_API int remove_threat(const char* malware_id);

THREATDB_API int get_threat(const char* malware_id, ThreatEntry* entry);
THREATDB_API int find_threat_by_name(const char* name, ThreatEntry* entries, int max_entries);
THREATDB_API int find_threats_by_family(const char* family, ThreatEntry* entries, int max_entries);

THREATDB_API int get_all_threats(ThreatEntry* entries, int max_entries);
THREATDB_API int get_threat_count();

THREATDB_API int get_database_info(ThreatDatabaseInfo* info);

THREATDB_API int search_threats(const char* query, ThreatEntry* entries, int max_entries);

THREATDB_API int sync_database(const char* remote_url);
THREATDB_API int verify_database_integrity();

THREATDB_API int export_iocs(const char* filepath, const char* format);
THREATDB_API int import_iocs(const char* filepath, const char* format);

THREATDB_API const char* get_database_version();

#ifdef __cplusplus
}
#endif

#endif