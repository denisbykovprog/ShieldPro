#include "mem_scanner.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <algorithm>
#include <map>

static bool g_initialized = false;
static bool g_scanning = false;
static CRITICAL_SECTION g_cs;
static const char* VERSION = "1.0.0";

static std::map<unsigned long, std::vector<MemoryRegion>> g_memory_cache;

static void log_event(const char* msg) {
    EnterCriticalSection(&g_cs);
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string dir = path;
    size_t pos = dir.rfind('\\');
    if (pos != std::string::npos) dir = dir.substr(0, pos);
    dir += "\\..\\data\\logs\\mem_scanner.log";
    FILE* f = fopen(dir.c_str(), "a");
    if (f) {
        time_t now = time(nullptr);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(f, "[%s] %s\n", time_str, msg);
        fclose(f);
    }
    LeaveCriticalSection(&g_cs);
}

MEMSCAN_API int init_memory_scanner() {
    if (g_initialized) return 1;
    InitializeCriticalSection(&g_cs);
    g_initialized = true;
    g_scanning = false;
    log_event("Memory scanner initialized");
    return 1;
}

MEMSCAN_API void close_memory_scanner() {
    if (!g_initialized) return;
    g_memory_cache.clear();
    DeleteCriticalSection(&g_cs);
    g_initialized = false;
    log_event("Memory scanner closed");
}

MEMSCAN_API int enumerate_processes(ProcessInfo* processes, int max_count) {
    if (!g_initialized || !processes) return 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    int count = 0;
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (count >= max_count) break;

            ProcessInfo& info = processes[count];
            info.pid = pe.th32ProcessID;
            wcscpy((wchar_t*)info.process_name, pe.szExeFile);
            info.thread_count = pe.cntThreads;
            info.module_count = 0;
            info.is_suspicious = 0;
            info.threat_score = 0.0;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProcess) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    info.working_set = pmc.WorkingSetSize;
                    info.private_bytes = pmc.PrivateUsage;
                }
                CloseHandle(hProcess);
            } else {
                info.working_set = 0;
                info.private_bytes = 0;
            }

            count++;
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return count;
}

MEMSCAN_API int get_process_info(unsigned long pid, ProcessInfo* info) {
    if (!g_initialized || !info || pid == 0) return 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    int found = 0;
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                info->pid = pid;
                wcscpy((wchar_t*)info->process_name, pe.szExeFile);
                info->thread_count = pe.cntThreads;

                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (hProcess) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                        info->working_set = pmc.WorkingSetSize;
                        info.private_bytes = pmc.PrivateUsage;
                    }
                    CloseHandle(hProcess);
                }

                found = 1;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return found;
}

MEMSCAN_API int scan_process_memory(unsigned long pid, MemoryThreat* threats, int max_threats) {
    if (!g_initialized || !threats || pid == 0) return 0;

    EnterCriticalSection(&g_cs);
    g_scanning = true;
    LeaveCriticalSection(&g_cs);

    int count = 0;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        EnterCriticalSection(&g_cs);
        g_scanning = false;
        LeaveCriticalSection(&g_cs);
        return 0;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* addr = (unsigned char*)si.lpMinimumApplicationAddress;

    while (addr < (unsigned char*)si.lpMaximumApplicationAddress && count < max_threats) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & PAGE_READABLE) &&
                !(mbi.Protect & PAGE_GUARD)) {

                if (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) {
                    unsigned long bytes_read = 0;
                    unsigned char buffer[4096];

                    if (mbi.RegionSize > 4096) {
                        if (ReadProcessMemory(hProcess, addr, buffer, 4096, &bytes_read)) {
                            for (int i = 0; i < bytes_read - 64 && count < max_threats; i++) {
                                if (buffer[i] == 0x4D && buffer[i+1] == 0x5A) {
                                    MemoryThreat& threat = threats[count++];
                                    threat.pid = pid;
                                    threat.address = (unsigned long)(addr + i);
                                    threat.size = bytes_read - i;
                                    threat.is_injected = 1;
                                    threat.is_hidden = 0;
                                    threat.threat_score = 75.0;
                                    memset(threat.content, 0, 256);
                                    memcpy(threat.content, buffer + i, min(256, bytes_read - i));
                                }
                            }
                        }
                    }
                }
            }
            addr += mbi.RegionSize;
        } else {
            addr += 4096;
        }
    }

    CloseHandle(hProcess);

    EnterCriticalSection(&g_cs);
    g_scanning = false;
    LeaveCriticalSection(&g_cs);

    return count;
}

MEMSCAN_API int scan_all_processes(MemoryThreat* threats, int max_threats, int* scanned_processes) {
    if (!g_initialized || !threats || !scanned_processes) return 0;

    int total_threats = 0;
    *scanned_processes = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            int threats_found = scan_process_memory(pe.th32ProcessID, threats + total_threats,
                                                   max_threats - total_threats);
            if (threats_found > 0) {
                total_threats += threats_found;
            }
            (*scanned_processes)++;
        } while (Process32NextW(hSnapshot, &pe) && total_threats < max_threats);
    }

    CloseHandle(hSnapshot);
    return total_threats;
}

MEMSCAN_API int get_memory_regions(unsigned long pid, MemoryRegion* regions, int max_regions) {
    if (!g_initialized || !regions || pid == 0) return 0;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return 0;

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    int count = 0;
    unsigned char* addr = (unsigned char*)si.lpMinimumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    while (addr < (unsigned char*)si.lpMaximumApplicationAddress && count < max_regions) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
            MemoryRegion& region = regions[count++];
            region.base_address = (unsigned long)addr;
            region.size = mbi.RegionSize;
            region.is_executable = (mbi.Protect & PAGE_EXECUTE) != 0;
            region.is_writable = (mbi.Protect & PAGE_WRITECOPY) != 0 || (mbi.Protect & PAGE_READWRITE) != 0;
            region.is_copy_on_write = (mbi.Protect & PAGE_WRITECOPY) != 0;
            region.entropy = 0;

            memset(region.section_name, 0, 10);

            if (mbi.Type == MEM_PRIVATE) strcpy_s(region.section_name, "Private");
            else if (mbi.Type == MEM_IMAGE) strcpy_s(region.section_name, "Image");
            else if (mbi.Type == MEM_MAPPED) strcpy_s(region.section_name, "Mapped");

            addr += mbi.RegionSize;
        } else {
            addr += 4096;
        }
    }

    CloseHandle(hProcess);
    return count;
}

MEMSCAN_API int detect_injected_dlls(unsigned long pid, char* dll_paths, int max_paths) {
    if (!g_initialized || !dll_paths || pid == 0) return 0;

    int count = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    }

    MODULEENTRY32W me;
    me.dwSize = sizeof(MODULEENTRY32W);

    if (pid == GetCurrentProcessId()) {
        if (Module32FirstW(hSnapshot, &me)) {
            do {
                if (count >= max_paths) break;
                WideCharToMultiByte(CP_ACP, 0, me.szExePath, -1, dll_paths + count * MAX_PATH, MAX_PATH, NULL, NULL);
                count++;
            } while (Module32NextW(hSnapshot, &me));
        }
    } else {
        if (Module32FirstW(hSnapshot, &me)) {
            do {
                if (count >= max_paths) break;
                WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, dll_paths + count * MAX_PATH, MAX_PATH, NULL, NULL);
                count++;
            } while (Module32NextW(hSnapshot, &me));
        }
    }

    CloseHandle(hSnapshot);
    return count;
}

MEMSCAN_API int detect_shellcode(unsigned long pid, MemoryThreat* threats, int max_threats) {
    return scan_process_memory(pid, threats, max_threats);
}

MEMSCAN_API int suspend_process(unsigned long pid) {
    if (!g_initialized || pid == 0) return 0;

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    int suspended = 0;
    if (Thread32First(hThreadSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                    suspended++;
                }
            }
        } while (Thread32Next(hThreadSnap, &te));
    }

    CloseHandle(hThreadSnap);
    return suspended;
}

MEMSCAN_API int resume_process(unsigned long pid) {
    if (!g_initialized || pid == 0) return 0;

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    int resumed = 0;
    if (Thread32First(hThreadSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) {
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                    resumed++;
                }
            }
        } while (Thread32Next(hThreadSnap, &te));
    }

    CloseHandle(hThreadSnap);
    return resumed;
}

MEMSCAN_API int terminate_process(unsigned long pid, int force) {
    if (!g_initialized || pid == 0) return 0;

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return 0;

    DWORD exit_code = force ? 1 : 0;
    int result = TerminateProcess(hProcess, exit_code);
    CloseHandle(hProcess);

    return result ? 1 : 0;
}

MEMSCAN_API int create_process_dump(unsigned long pid, const char* dump_path) {
    if (!g_initialized || !dump_path || pid == 0) return 0;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return 0;

    HANDLE hFile = CreateFileA(dump_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return 0;
    }

    BOOL result = MiniDumpWriteProcess(hProcess, pid, hFile, MiniDumpNormal, NULL, NULL, NULL);

    CloseHandle(hFile);
    CloseHandle(hProcess);

    return result ? 1 : 0;
}

MEMSCAN_API const char* get_scanner_version() {
    return VERSION;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: init_memory_scanner(); break;
        case DLL_PROCESS_DETACH: close_memory_scanner(); break;
    }
    return TRUE;
}