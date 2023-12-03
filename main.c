#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <setupapi.h>
#include <math.h>
#include "DXBCChecksum.h"

BOOL SetPrivilege(
        HANDLE hToken,          // access token handle
        LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
        BOOL bEnablePrivilege   // to enable or disable privilege
) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup
            &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(
            hToken,
            FALSE,
            &tp,
            sizeof(TOKEN_PRIVILEGES),
            (PTOKEN_PRIVILEGES) NULL,
            (PDWORD) NULL)) {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

MODULEENTRY32 GetModuleEntry(DWORD dwProcessId, const char *moduleName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &moduleEntry)) {
            do {
                if (strcmp(moduleEntry.szModule, moduleName) == 0) {
                    CloseHandle(hSnapshot);
                    return moduleEntry;
                }
            } while (Module32Next(hSnapshot, &moduleEntry));
        }
        CloseHandle(hSnapshot);
    }
    MODULEENTRY32 result = {0};
    return result;
}

DWORD currentSessionId;

DWORD FindProcess(const char *name) {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hProcessSnap, &processEntry)) {
            do {
                if (strcmp(processEntry.szExeFile, name) == 0) {
                    DWORD pid = processEntry.th32ProcessID;

                    DWORD sessionId;
                    if (ProcessIdToSessionId(pid, &sessionId)) {
                        if (currentSessionId == sessionId) {
                            return pid;
                        }
                    }
                }
            } while (Process32Next(hProcessSnap, &processEntry));
        }
        CloseHandle(hProcessSnap);
    }
    return 0;
}

DWORD FindProcessRetry(const char *name) {
    DWORD pid = 0;
    while (pid == 0) {
        pid = FindProcess(name);
    }
    return pid;
}

typedef struct DXBCShader {
    char magic[4];
    DWORD checksum[4];
    DWORD reserved;
    DWORD size;
    unsigned char rest[];
} DXBCShader;

void FixChecksum(DXBCShader *shader) {
    BYTE *raw = (BYTE *) shader;
    CalculateDXBCChecksum(raw, shader->size, shader->checksum);
}

float srgbConstants[] = {2.4f, 0.04045f, 0.055000f, 0.94786733f};
float patchedConstants[] = {2.4f, 0, 0, 1};

BOOL PatchShader(DXBCShader *shader) {
    BYTE *raw = (BYTE *) shader;
    for (int i = 0; i < sizeof(srgbConstants) / sizeof(srgbConstants[0]); i++) {
        float constant = srgbConstants[i];
        float target[3] = {constant, constant, constant};
        for (size_t j = offsetof(DXBCShader, rest); j <= shader->size - sizeof(float); j++) {
            if (memcmp((BYTE *) target, raw + j, sizeof(target)) != 0) continue;

            float patch = patchedConstants[i];

            printf("patching %f to %f\n", constant, patch);
            for (int k = 0; k < 3; k++) {
                ((float *) (raw + j))[k] = patch;
            }
        }
    }

    FixChecksum(shader);

    return TRUE;
}

BOOL WriteShader(HANDLE proc, BYTE *addr, DXBCShader *shader) {
    DWORD oldprotect;
    VirtualProtectEx(proc, addr, shader->size, PAGE_READWRITE, &oldprotect);

    if (!WriteProcessMemory(proc, addr, (BYTE *) shader, shader->size, NULL)) {
        printf("Failed to write memory to dwm.exe process.\n");
        VirtualProtectEx(proc, addr, shader->size, oldprotect, NULL);
        CloseHandle(proc);
        return FALSE;
    }

    printf("Buffer written successfully.\n");

    VirtualProtectEx(proc, addr, shader->size, oldprotect, NULL);

    return TRUE;
}

int patched = 0;

BOOL FindAndPatchShaders(BYTE *buffer, size_t size, BYTE *real, HANDLE proc) {
    BYTE hashes[][16] = {
            {0x96, 0xe6, 0xd1, 0x58, 0x92, 0x55, 0xec, 0xcd, 0x1d, 0xd7, 0xd4, 0xdb, 0xec, 0x54, 0xd2, 0x85},
            {0x21, 0x26, 0xb0, 0x37, 0xc1, 0xa2, 0xfb, 0xdd, 0xe3, 0x55, 0xb6, 0xe6, 0xdd, 0x9c, 0xaf, 0x3c},
            {0x2c, 0x89, 0x26, 0xff, 0xe2, 0x29, 0xf0, 0x5d, 0x96, 0x7c, 0x72, 0x66, 0x8d, 0xc3, 0xad, 0xdb},
            {0xf6, 0x93, 0xbf, 0xbb, 0xaf, 0x24, 0xb3, 0xd9, 0x36, 0x63, 0x54, 0xbe, 0x88, 0x98, 0xa7, 0xf5}
    };

    int num_hashes = sizeof(hashes) / sizeof(hashes[0]);

    DXBCShader *bigShader = 0;
    int bigShaderPatched = 0;
    for (int i = 0; i <= size - sizeof(DXBCShader); i++) {
        if (bigShader && buffer + i >= (BYTE *) bigShader + bigShader->size) {
            if (bigShaderPatched) {
                printf("Fixing up checksum of big shader %p\n", bigShader);
                FixChecksum(bigShader);

                printf("Writing back big shader\n");

                BYTE *big_real = (BYTE *) bigShader - buffer + real;
                if (!WriteShader(proc, big_real, bigShader)) {
                    printf("Failed to write big shader\n");
                    return FALSE;
                }

            }
            bigShader = 0;
            bigShaderPatched = 0;
        }

        DXBCShader *shader = (DXBCShader *) (buffer + i);
        if (!(shader->magic[0] == 'D' && shader->magic[1] == 'X' && shader->magic[2] == 'B' &&
              shader->magic[3] == 'C'))
            continue;
        if (shader->reserved != 1) continue;

        int k = -1;
        for (int j = 0; j < num_hashes; j++) {
            if (!memcmp(hashes[j], shader->checksum, sizeof(hashes[0]))) {
                k = j;
                break;
            }
        }

        if (k == -1) {
            if (!bigShader || (BYTE *) shader >= (BYTE *) bigShader + bigShader->size) {
                bigShader = shader;
            }
            continue;
        }

        printf("patching shader #%d\n", k);

        if (!PatchShader(shader)) {
            printf("Error on patching shader #%d\n", k);
            return FALSE;
        }

        printf("this belonged to big shader %p\n", bigShader);

        BYTE *shader_real = real + i;

        if (!bigShader) {
            printf("Writing back shader\n");
            if (!WriteShader(proc, shader_real, shader)) {
                printf("Failed to write shader #%d\n", k);
                return FALSE;
            }
        }

        patched++;

        if (bigShader) {
            bigShaderPatched++;
        }
    }

    return TRUE;
}

typedef LONG (NTAPI *NtSuspendProcess_t)(IN HANDLE ProcessHandle);

typedef LONG (NTAPI *NtResumeProcess_t)(IN HANDLE ProcessHandle);

int main(int argc, char *argv[]) {
    if (argc > 3) {
        printf("Usage: dwm_eotf [gamma [scale factor]]\n");
        return 1;
    }
    if (argc >= 2) {
        float gamma = atof(argv[1]);
        if (gamma < 1 || gamma > 10) {
            printf("Got invalid gamma value %f, exiting\n", gamma);
            return 1;
        }

        patchedConstants[0] = gamma;
    }
    if (argc == 3) {
        float scale = atof(argv[2]);
        if (scale < 0.01 || scale > 10) {
            printf("Got invalid scale factor %f, exiting\n", scale);
            return 1;
        }

        patchedConstants[3] = powf(sqrtf(scale), 1 / patchedConstants[0]);
    }

    currentSessionId = WTSGetActiveConsoleSessionId();

    NtSuspendProcess_t NtSuspendProcess = (NtSuspendProcess_t) GetProcAddress(GetModuleHandleA("ntdll"),
                                                                              "NtSuspendProcess");
    NtResumeProcess_t NtResumeProcess = (NtResumeProcess_t) GetProcAddress(GetModuleHandleA("ntdll"),
                                                                           "NtResumeProcess");

    if (!NtSuspendProcess || !NtResumeProcess) {
        printf("Failed to get ntdll functions\n");
    }

    BOOL isOK;
    HANDLE hToken;
    HANDLE hCurrentProcess;
    hCurrentProcess = GetCurrentProcess();
    isOK = OpenProcessToken(hCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);

    DWORD dwmProcessId = FindProcessRetry("dwm.exe");

    printf("got pid %lu\n", dwmProcessId);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwmProcessId);
    if (hProcess == NULL) {
        printf("Failed to open dwm.exe process.\n");
        return 1;
    }

    printf("Killing dwm...\n");

    TerminateProcess(hProcess, 0);
    CloseHandle(hProcess);

    {
        DWORD newPid = dwmProcessId;
        while (newPid == dwmProcessId) {
            newPid = FindProcessRetry("dwm.exe");
        }
        dwmProcessId = newPid;
    }

    printf("Got new pid %lu\n", dwmProcessId);

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwmProcessId);
    if (hProcess == NULL) {
        printf("Failed to open dwm.exe process.\n");
        return 1;
    }

    MODULEENTRY32 dwmcore;

    while (1) {
        dwmcore = GetModuleEntry(dwmProcessId, "dwmcore.dll");
        if (dwmcore.modBaseAddr == 0) {
            printf("Could not find dwmcore.dll, retrying.\n");
            continue;
        }
        break;
    }

    printf("Got dwmcore.dll, suspending process\n");

    if (NtSuspendProcess(hProcess)) {
        printf("Failed to suspend dwm.exe\n");
        return 1;
    }

    BYTE *addr = dwmcore.modBaseAddr;
    size_t offset = 0;
    size_t bytesRead;

    MEMORY_BASIC_INFORMATION mbi = {0};

    while (VirtualQueryEx(hProcess, addr + offset, &mbi, sizeof(mbi))) {
        if (mbi.RegionSize > 4096 && mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READONLY) {
            BYTE buffer[mbi.RegionSize];

            ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);

            if (mbi.RegionSize != bytesRead) {
                printf("tried to read %zu bytes, got %zu\n", mbi.RegionSize, bytesRead);
                NtResumeProcess(hProcess);
                CloseHandle(hProcess);
                return 1;
            }

            printf("read memory region containing shaders (hopefully)\n");

            if (!FindAndPatchShaders(buffer, mbi.RegionSize, mbi.BaseAddress, hProcess)) {
                printf("Error on patching shaders\n");
                NtResumeProcess(hProcess);
                CloseHandle(hProcess);
                return 1;
            }

            break;
        }
        offset += mbi.RegionSize;

        if (addr + offset > dwmcore.modBaseAddr + dwmcore.modBaseSize) {
            printf("failed to get memory region\n");
            NtResumeProcess(hProcess);
            CloseHandle(hProcess);
            return 1;
        }
    }

    printf("%d shaders patched", patched);

    if (patched == 0) {
        printf(" - try running it again?");
    }

    printf("\n");

    printf("All done! Resuming dwm...\n");

    NtResumeProcess(hProcess);
    CloseHandle(hProcess);

    printf("All good?\n");

    system("pause");

    return 0;
}
