/*
 * Sentinel.exe - tiny native launcher.
 *
 * Starts the bundled interpreter:   <here>\runtime\python\python.exe -m sentinel.launcher <your args>
 * so the whole product is one folder that needs no installed Python, no VC++ redistributable and no PATH edits.
 *
 *  - Sets SENTINEL_HOME / SENTINEL_EXE / PYTHONPATH for the child only.
 *  - Puts the child in a job object, so stopping this process (e.g. ending the scheduled task) also stops the server.
 *  - Swallows Ctrl+C in the launcher; the console delivers it to Python, which shuts down cleanly.
 *
 * Build (any OS):  python -m ziglang cc -target x86_64-windows-gnu -O2 -s -municode launcher.c -o Sentinel.exe
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static BOOL WINAPI on_ctrl(DWORD type) {
    return (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) ? TRUE : FALSE;
}

/* Return the part of the command line after argv[0]. */
static const wchar_t *skip_program_name(const wchar_t *cl) {
    if (*cl == L'"') {
        cl++;
        while (*cl && *cl != L'"') cl++;
        if (*cl == L'"') cl++;
    } else {
        while (*cl && *cl != L' ' && *cl != L'\t') cl++;
    }
    while (*cl == L' ' || *cl == L'\t') cl++;
    return cl;
}

int wmain(void) {
    wchar_t exe[MAX_PATH * 2], home[MAX_PATH * 2], py[MAX_PATH * 2 + 40], app[MAX_PATH * 2 + 8];
    DWORD n = GetModuleFileNameW(NULL, exe, (DWORD)(sizeof(exe) / sizeof(exe[0])));
    if (n == 0 || n >= sizeof(exe) / sizeof(exe[0])) {
        fwprintf(stderr, L"Sentinel: cannot determine its own location.\n");
        return 2;
    }
    wcscpy(home, exe);
    wchar_t *slash = wcsrchr(home, L'\\');
    if (!slash) { fwprintf(stderr, L"Sentinel: unexpected executable path.\n"); return 2; }
    *slash = 0;

    swprintf(py, sizeof(py) / sizeof(py[0]), L"%ls\\runtime\\python\\python.exe", home);
    swprintf(app, sizeof(app) / sizeof(app[0]), L"%ls\\app", home);
    if (GetFileAttributesW(py) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"Sentinel: bundled Python not found at\n  %ls\nThe package looks incomplete; re-extract it fully.\n", py);
        return 2;
    }

    SetEnvironmentVariableW(L"SENTINEL_HOME", home);
    SetEnvironmentVariableW(L"SENTINEL_EXE", exe);
    SetEnvironmentVariableW(L"PYTHONPATH", app);
    SetEnvironmentVariableW(L"PYTHONNOUSERSITE", L"1");
    SetEnvironmentVariableW(L"PYTHONDONTWRITEBYTECODE", L"1");
    SetEnvironmentVariableW(L"PYTHONUTF8", L"1");
    SetEnvironmentVariableW(L"PYTHONHOME", NULL);   /* never inherit a stray PYTHONHOME from the machine */

    const wchar_t *args = skip_program_name(GetCommandLineW());
    size_t len = wcslen(py) + wcslen(args) + 64;
    wchar_t *cmd = (wchar_t *)malloc(len * sizeof(wchar_t));
    if (!cmd) return 2;
    swprintf(cmd, len, L"\"%ls\" -m sentinel.launcher %ls", py, args);

    SetConsoleCtrlHandler(on_ctrl, TRUE);

    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
        ZeroMemory(&info, sizeof(info));
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info));
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(py, cmd, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, home, &si, &pi)) {
        fwprintf(stderr, L"Sentinel: could not start Python (error %lu).\n", GetLastError());
        return 2;
    }
    if (job) AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
}
