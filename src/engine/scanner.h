#ifndef SCANNER_H
#define SCANNER_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SIGNATURES 10000
#define MAX_SIGNATURE_NAME 256
#define MAX_PATH_LEN 1024
#define BUFFER_SIZE 65536
#define HASH_SIZE 32

typedef struct {
    char name[MAX_SIGNATURE_NAME];
    unsigned char signature[256];
    int sig_length;
    int is_hex;
} Signature;

typedef struct {
    Signature signatures[MAX_SIGNATURES];
    int count;
    int loaded;
} SignatureDatabase;

typedef struct {
    char path[MAX_PATH_LEN];
    int infected;
    char threat_name[MAX_SIGNATURE_NAME];
    int threat_type;
    double confidence;
} ScanResult;

typedef struct {
    char file_hash[HASH_SIZE * 2 + 1];
    char threat_name[MAX_SIGNATURE_NAME];
} HashEntry;

int init_scanner(const char* db_path);
void close_scanner(void);
int load_signatures(const char* sig_file);
int scan_file(const char* filepath, char* threat_name, int name_size, int* threat_type);
int scan_buffer(const unsigned char* buffer, int size, char* threat_name, int name_size);
int scan_directory(const char* dirpath, void (*callback)(const char*, int, const char*, void*), void* user_data);
int compute_file_hash(const char* filepath, char* hash_output);
int quick_scan(const char* filepath);
const char* get_scanner_version(void);
int get_signature_count(void);
int reload_signatures(void);

#ifdef __cplusplus
}
#endif

#endif