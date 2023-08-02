#include <Windows.h>

DWORD dwCL_MoveOffset=0xBC1E0;

using CLMove_t=void(__cdecl*)(float,bool);
CLMove_t oCLMove;

int CommandsToRun=10;

void __cdecl hkCLMove(float accumulated_extra_samples,bool bFinalTick)
{
    if(GetAsyncKeyState('C'))
        return;

    oCLMove(accumulated_extra_samples,bFinalTick);

    if(GetAsyncKeyState('V'))
    {
        for(int i=0;i<CommandsToRun;++i)
        {
            oCLMove(accumulated_extra_samples,i==CommandsToRun-1);
        }
    }
}

bool Hook(BYTE* src,BYTE* dst,uintptr_t len)
{
    if(len<5) return false;

    DWORD dwOldProtect;
    VirtualProtect(src,len,PAGE_EXECUTE_READWRITE,&dwOldProtect);

    uintptr_t relativeAddress=dst-src-5;

    *src=0xE9;
    *(uintptr_t*)(src+1)=relativeAddress;

    VirtualProtect(src,len,dwOldProtect,&dwOldProtect);
    return true;
}

BYTE* TrampHook(BYTE* src,BYTE* dst,uintptr_t len)
{
    if(len<5) return NULL;

    BYTE* gateway=(BYTE*)VirtualAlloc(NULL,len,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    memcpy(gateway,src,len);

    uintptr_t gatewayRelativeAddress=src-gateway-5;

    *(gateway+len)=0xE9;
    *(uintptr_t*)((uintptr_t)gateway+len+1)=gatewayRelativeAddress;

    Hook(src,dst,len);
    return gateway;
}

void Unhook(BYTE* src,BYTE* gateway,uintptr_t len)
{
    DWORD dwOldProtect;
    VirtualProtect(src,len,PAGE_EXECUTE_READWRITE,&dwOldProtect);

    memcpy(src,gateway,len);

    VirtualProtect(src,len,dwOldProtect,&dwOldProtect);

    VirtualFree(gateway,len,MEM_RELEASE);
}

DWORD WINAPI HackThread(HMODULE hModule)
{
    HMODULE hEngine=GetModuleHandleW(L"engine.dll");

    BYTE* CLMove=(BYTE*)((DWORD)hEngine+dwCL_MoveOffset);
    oCLMove=(CLMove_t)TrampHook(CLMove,(BYTE*)hkCLMove,6);

    while(!GetAsyncKeyState(VK_DELETE))
    {
        Sleep(2000);
    }

    Unhook(CLMove,(BYTE*)oCLMove,6);

    FreeLibraryAndExitThread(hModule,0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,DWORD ul_reason_for_call,LPVOID lpReserved)
{
    if(ul_reason_for_call==DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        HANDLE hThread=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)HackThread,hModule,0,NULL);
        if(hThread)
        {
            CloseHandle(hThread);
        }
    }

    return TRUE;
}

