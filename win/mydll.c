// mydll.c
#include <windows.h>

// Exported functions
__declspec(dllexport) int add(int a, int b) {
    return a + b;
}

__declspec(dllexport) int subtract(int a, int b) {
    return a - b;
}

__declspec(dllexport) int multiply(int a, int b) {
    return a * b;
}

// Required for DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
