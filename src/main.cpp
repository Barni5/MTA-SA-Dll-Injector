#define _CRT_SECURE_NO_WARNINGS

#include <string>
#include <chrono>
#include <vector>
#include <random>
#include <thread>

#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <wchar.h>
#include <wininet.h>
#include <commdlg.h>
#include <atomic>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")

using namespace std;

bool OpenSelectMenu(char* selectedFilePath, int bufferSize) {
    OPENFILENAMEA ofn;
    char fileName[MAX_PATH] = "";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetConsoleWindow();
    ofn.lpstrFilter = "DLL Files\0*.dll\0All Files\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameA(&ofn)) {
        strncpy(selectedFilePath, fileName, bufferSize);
        return true;
    }
    return false;
}

DWORD FindProcessID(const char* processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(hSnapshot, &processEntry)) {
        do {
            char exeFile[MAX_PATH];
            size_t convertedChars = 0;
            wcstombs_s(&convertedChars, exeFile, MAX_PATH, processEntry.szExeFile, _TRUNCATE);

            if (strcmp(exeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }

    CloseHandle(hSnapshot);
    return 0;
}

bool InjectDLL(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        return false;
    }

    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pDllPath) {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dllPath, strlen(dllPath) + 1, NULL)) {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    BYTE hookCode[] = {
        0x68, 0, 0, 0, 0,  // push (dll path)
        0xB8, 0, 0, 0, 0,  // mov eax LoadLibraryA (LoadLibraryA into eax register)
        0xFF, 0xD0,        // call eax (Execute LoadLibraryA)
        0xC3               // return
    };

    *reinterpret_cast<LPVOID*>(&hookCode[1]) = pDllPath;
    *reinterpret_cast<LPVOID*>(&hookCode[6]) = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    LPVOID pHook = VirtualAllocEx(hProcess, NULL, sizeof(hookCode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pHook) {
        cout << "[-] Failed to find memory for hook." << endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pHook, hookCode, sizeof(hookCode), NULL)) {
        cout << "[-] Failed to write hook code." << endl;
        VirtualFreeEx(hProcess, pHook, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pHook, NULL, 0, NULL);
    if (!hThread) {
        cout << "[-] Failed to create thread." << endl;
        VirtualFreeEx(hProcess, pHook, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pHook, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

void FPDelete() {
    const char* fppaths[] = {
        "C:\\ProgramData\\MTA San Andreas All\\Common\\temp2\\FairplayKD.sys",
        "C:\\ProgramData\\MTA San Andreas All\\Common\\temp\\FairplayKD.sys",
        "C:\\ProgramData\\MTA San Andreas All\\1.6\\temp\\FairplayKD.sys",
        "C:\\ProgramData\\MTA San Andreas All\\1.6\\temp2\\FairplayKD.sys"
    };
    for (const char* path : fppaths) {
        DeleteFileA(path);
        Sleep(100);
    }
}

void FPBypass() {
    ShellExecuteA(
        GetConsoleWindow(),
        "open",
        "cmd.exe",
        "/k \"@echo off & for /l %x in (0, 0, 1) do (sc stop FairplayKD0 & sc stop FairplayKD & sc stop FairplayKD1 & sc stop FairplayKD2 & sc stop FairplayKD3 & sc stop FairplayKD4 & sc stop FairplayKD5 & sc stop FairplayKD6 & sc stop FairplayKD7 & sc stop FairplayKD8 & sc stop FairplayKD9 & sc stop FairplayKD10)\"",
        0,
        SW_HIDE
    );

    ShellExecuteA(
        GetConsoleWindow(),
        "open",
        "cmd.exe",
        "/k \"@echo off & for /l %x in (0, 0, 1) do (del /q \"C:\\ProgramData\\MTA San Andreas All\\Common\\temp\\FairplayKD.sys\" & del /q \"C:\\ProgramData\\MTA San Andreas All\\Common\\temp2\\FairplayKD.sys\" & del /q \"C:\\ProgramData\\MTA San Andreas All\\1.6\\temp\\FairplayKD.sys\")\"",
        0,
        SW_HIDE
    );
}

int main() {
    SetConsoleTitleW(L"");
    system("cls");
    cout << "[+] This is just a simple dll injection\n";
    cout << "[+] Use a netc bypass with this (or mta will block the injection lol)\n";
    Sleep(100);
    cout << "[+] Fairplay bypass (i hate myself for this)\n";
    FPDelete();
    FPBypass();
    Sleep(500);

    char dllpath[MAX_PATH];

    if (!OpenSelectMenu(dllpath, MAX_PATH)) {
        cout << "[-] ERROR (1)\n";
        system("cls");
        system("taskkill /F /IM cmd.exe");
        return 1;
    }

    DWORD processID = 0;
    int dots = 0;
    while (processID == 0) {
        processID = FindProcessID("gta_sa.exe");
        cout << ".";
        dots++;
        if (dots > 3) {
            cout << "\r[*] OPEN MTA (gta_sa.exe)   ";
            dots = 0;
        }
        Sleep(500);
    }
    cout << "\n[+] MTA FOUND (PID: " << processID << ")\n";

    if (!InjectDLL(processID, dllpath)) {
        cout << "[-] ERROR (2)\n";
        system("cls");
        system("taskkill /F /IM cmd.exe");
        return 1;
    }
    cout << "[+] DONE!\n";

    Beep(1000, 500);
    Sleep(1000);
    system("cls");
    system("taskkill /F /IM cmd.exe");

    return 0;
}