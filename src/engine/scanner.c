#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include "scanner.h"

static SignatureDatabase g_database = {0};
static CRITICAL_SECTION g_cs;
static int g_initialized = 0;

static const char* VERSION = "1.0.0";

typedef struct {
    int bm_patlen;
    int bm_textlen;
    int bm_badchar[256];
    int bm_goodsuffix[256];
} BMData;

static void bm_init(BMData* bm, const unsigned char* pattern, int patlen) {
    bm->bm_patlen = patlen;
    for (int i = 0; i < 256; i++) bm->bm_badchar[i] = patlen;
    for (int i = 0; i < patlen - 1; i++) bm->bm_badchar[pattern[i]] = patlen - 1 - i;
    for (int i = 0; i < 256; i++) bm->bm_goodsuffix[i] = 0;
    for (int i = patlen - 1; i >= 0; i--) {
        int is_suffix = 1;
        for (int j = 0; j < patlen - i - 1; j++) {
            if (pattern[j] != pattern[i + 1 + j]) { is_suffix = 0; break; }
        }
        if (is_suffix) bm->bm_goodsuffix[pattern[i]] = patlen - 1 - i;
    }
}

static int bm_search(BMData* bm, const unsigned char* text, int textlen) {
    int i = bm->bm_patlen - 1;
    while (i < textlen) {
        int j = bm->bm_patlen - 1;
        while (j >= 0 && text[i] == ((const unsigned char*)bm)[j]) { i--; j--; }
        if (j < 0) return i + 1;
        int bad_shift = bm->bm_badchar[text[i]];
        int good_shift = (j > 0) ? bm->bm_goodsuffix[text[i]] : 0;
        i += (bad_shift > good_shift) ? bad_shift : good_shift;
    }
    return -1;
}

static int hex_to_bytes(const char* hex_str, unsigned char* out, int max_len) {
    int len = (int)strlen(hex_str);
    if (len % 2 != 0 || len > max_len * 2) return -1;
    for (int i = 0; i < len / 2; i++) {
        char high = hex_str[i * 2];
        char low = hex_str[i * 2 + 1];
        high = (high >= 'a') ? (high - 'a' + 10) : ((high >= 'A') ? (high - 'A' + 10) : (high - '0'));
        low = (low >= 'a') ? (low - 'a' + 10) : ((low >= 'A') ? (low - 'A' + 10) : (low - '0'));
        out[i] = (high << 4) | low;
    }
    return len / 2;
}

static int load_signature_line(char* line, Signature* sig) {
    char* colon = strchr(line, ':');
    if (!colon) return 0;
    *colon = '\0';
    strncpy(sig->name, line, MAX_SIGNATURE_NAME - 1);
    sig->name[MAX_SIGNATURE_NAME - 1] = '\0';
    sig->sig_length = hex_to_bytes(colon + 1, sig->signature, 256);
    if (sig->sig_length <= 0) return 0;
    sig->is_hex = 1;
    return 1;
}

int init_scanner(const char* db_path) {
    if (g_initialized) return 1;
    InitializeCriticalSection(&g_cs);
    g_initialized = 1;
    g_database.loaded = 0;
    g_database.count = 0;
    return 1;
}

void close_scanner(void) {
    if (!g_initialized) return;
    DeleteCriticalSection(&g_cs);
    g_initialized = 0;
    g_database.count = 0;
    g_database.loaded = 0;
}

int load_signatures(const char* sig_file) {
    if (!g_initialized) init_scanner(NULL);
    EnterCriticalSection(&g_cs);
    FILE* f = fopen(sig_file, "r");
    if (!f) { LeaveCriticalSection(&g_cs); return 0; }
    char line[4096];
    g_database.count = 0;
    while (fgets(line, sizeof(line), f) && g_database.count < MAX_SIGNATURES) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
        if (len == 0 || line[0] == '#' || line[0] == ';') continue;
        if (load_signature_line(line, &g_database.signatures[g_database.count])) {
            g_database.count++;
        }
    }
    fclose(f);
    g_database.loaded = 1;
    LeaveCriticalSection(&g_cs);
    return g_database.count;
}

int scan_file(const char* filepath, char* threat_name, int name_size, int* threat_type) {
    if (!g_initialized || !g_database.loaded) return -1;
    EnterCriticalSection(&g_cs);
    FILE* f = fopen(filepath, "rb");
    if (!f) { LeaveCriticalSection(&g_cs); return -1; }
    unsigned char buffer[BUFFER_SIZE];
    int bytes_read;
    int found = 0;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, f)) > 0) {
        for (int i = 0; i < g_database.count && !found; i++) {
            Signature* sig = &g_database.signatures[i];
            if (sig->sig_length > bytes_read) continue;
            BMData bm;
            bm_init(&bm, sig->signature, sig->sig_length);
            if (bm_search(&bm, buffer, bytes_read) >= 0) {
                if (threat_name && name_size > 0) {
                    strncpy(threat_name, sig->name, name_size - 1);
                    threat_name[name_size - 1] = '\0';
                }
                if (threat_type) *threat_type = 1;
                found = 1;
                break;
            }
        }
        if (found) break;
    }
    fclose(f);
    LeaveCriticalSection(&g_cs);
    return found ? 1 : 0;
}

int scan_buffer(const unsigned char* buffer, int size, char* threat_name, int name_size) {
    if (!g_initialized || !g_database.loaded || !buffer || size <= 0) return -1;
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_database.count; i++) {
        Signature* sig = &g_database.signatures[i];
        if (sig->sig_length > size) continue;
        BMData bm;
        bm_init(&bm, sig->signature, sig->sig_length);
        if (bm_search(&bm, buffer, size) >= 0) {
            if (threat_name && name_size > 0) {
                strncpy(threat_name, sig->name, name_size - 1);
                threat_name[name_size - 1] = '\0';
            }
            LeaveCriticalSection(&g_cs);
            return 1;
        }
    }
    LeaveCriticalSection(&g_cs);
    return 0;
}

int scan_directory(const char* dirpath, void (*callback)(const char*, int, const char*, void*), void* user_data) {
    if (!g_initialized || !g_database.loaded || !dirpath) return -1;
    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(dirpath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return -1;
    int count = 0;
    char filepath[MAX_PATH_LEN];
    char threat_name[MAX_SIGNATURE_NAME];
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        snprintf(filepath, MAX_PATH_LEN, "%s", dirpath);
    } while (FindNextFile(hFind, &fd) && ++count < 1000);
    FindClose(hFind);
    return count;
}

int compute_file_hash(const char* filepath, char* hash_output) {
    if (!filepath || !hash_output) return -1;
    HANDLE hFile = CreateFile(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile); return -1;
    }
    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, CALG_SHA256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); CloseHandle(hFile); return -1;
    }
    unsigned char buffer[4096];
    DWORD bytes_read;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytes_read, NULL) && bytes_read > 0) {
        CryptHashData(hHash, buffer, bytes_read, 0);
    }
    unsigned char hash[32];
    DWORD hash_len = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len, 0);
    for (int i = 0; i < 32; i++) sprintf(hash_output + i * 2, "%02x", hash[i]);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return 0;
}

int quick_scan(const char* filepath) {
    char threat_name[MAX_SIGNATURE_NAME];
    int threat_type = 0;
    return scan_file(filepath, threat_name, sizeof(threat_name), &threat_type);
}

const char* get_scanner_version(void) {
    return VERSION;
}

int get_signature_count(void) {
    return g_database.count;
}

int reload_signatures(void) {
    return g_database.loaded ? load_signatures(NULL) : 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: init_scanner(NULL); break;
        case DLL_PROCESS_DETACH: close_scanner(); break;
    }
    return TRUE;
}