from pathlib import Path
import argparse

ap=argparse.ArgumentParser()
ap.add_argument('--script', required=True)
ap.add_argument('--ico', required=True)
ap.add_argument('--png', required=True)
ap.add_argument('--prefix', required=True)
ap.add_argument('--out', required=True)
a=ap.parse_args()

script=Path(a.script).read_bytes()
ico=Path(a.ico).read_bytes()
png=Path(a.png).read_bytes()
prefix=Path(a.prefix).read_text(encoding='utf-8')

def arr(name,data):
    lines=[]
    for i in range(0,len(data),20):
        chunk=data[i:i+20]
        lines.append('    '+','.join(f'0x{x:02x}' for x in chunk)+',')
    return f'static const unsigned char {name}[] = {{\n'+"\n".join(lines)+f'\n}};\nstatic const unsigned long {name}_size = {len(data)}UL;\n\n'

suffix=r'''
static WCHAR g_exePath[2048];
static WCHAR g_tempRoot[1024];
static WCHAR g_runDir[1400];
static WCHAR g_ps1Path[1800];
static WCHAR g_icoPath[1800];
static WCHAR g_pngPath[1800];
static WCHAR g_sysroot[1024];
static WCHAR g_psExe[1600];
static WCHAR g_cmd[8192];

static PFN_LoadLibraryW g_LoadLibraryW=NULL;
static PFN_MessageBoxW g_MessageBoxW=NULL;
static void show_error(const WCHAR* text) {
    if(!g_MessageBoxW && g_LoadLibraryW) {
        HMODULE u=g_LoadLibraryW(L"user32.dll");
        if(u) g_MessageBoxW=(PFN_MessageBoxW)resolve_export(u,"MessageBoxW");
    }
    if(g_MessageBoxW) g_MessageBoxW(NULL,text,L"Keenetic Config Manager 2.1.0 Test1",MB_ICONERROR);
}

static BOOL write_blob(PFN_CreateFileW CreateFileW, PFN_WriteFile WriteFile, PFN_CloseHandle CloseHandle,
                       LPCWSTR path, const unsigned char* data, DWORD size) {
    HANDLE hf=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_TEMPORARY,NULL);
    if(hf==INVALID_HANDLE_VALUE) return FALSE;
    DWORD wr=0; BOOL ok=WriteFile(hf,data,size,&wr,NULL); CloseHandle(hf);
    return ok && wr==size;
}

void WinMainCRTStartup(void) {
    void* k32=find_module_ascii("kernel32.dll");
    if(!k32) { for(;;){} }
    PFN_GetTempPathW GetTempPathW=(PFN_GetTempPathW)resolve_export(k32,"GetTempPathW");
    PFN_GetCurrentProcessId GetCurrentProcessId=(PFN_GetCurrentProcessId)resolve_export(k32,"GetCurrentProcessId");
    PFN_GetModuleFileNameW GetModuleFileNameW=(PFN_GetModuleFileNameW)resolve_export(k32,"GetModuleFileNameW");
    PFN_GetEnvironmentVariableW GetEnvironmentVariableW=(PFN_GetEnvironmentVariableW)resolve_export(k32,"GetEnvironmentVariableW");
    PFN_SetEnvironmentVariableW SetEnvironmentVariableW=(PFN_SetEnvironmentVariableW)resolve_export(k32,"SetEnvironmentVariableW");
    PFN_CreateFileW CreateFileW=(PFN_CreateFileW)resolve_export(k32,"CreateFileW");
    PFN_WriteFile WriteFile=(PFN_WriteFile)resolve_export(k32,"WriteFile");
    PFN_CloseHandle CloseHandle=(PFN_CloseHandle)resolve_export(k32,"CloseHandle");
    PFN_CreateDirectoryW CreateDirectoryW=(PFN_CreateDirectoryW)resolve_export(k32,"CreateDirectoryW");
    PFN_RemoveDirectoryW RemoveDirectoryW=(PFN_RemoveDirectoryW)resolve_export(k32,"RemoveDirectoryW");
    PFN_DeleteFileW DeleteFileW=(PFN_DeleteFileW)resolve_export(k32,"DeleteFileW");
    PFN_CreateProcessW CreateProcessW=(PFN_CreateProcessW)resolve_export(k32,"CreateProcessW");
    PFN_WaitForSingleObject WaitForSingleObject=(PFN_WaitForSingleObject)resolve_export(k32,"WaitForSingleObject");
    PFN_GetCommandLineW GetCommandLineW=(PFN_GetCommandLineW)resolve_export(k32,"GetCommandLineW");
    PFN_ExitProcess ExitProcess=(PFN_ExitProcess)resolve_export(k32,"ExitProcess");
    g_LoadLibraryW=(PFN_LoadLibraryW)resolve_export(k32,"LoadLibraryW");
    if(!GetTempPathW||!GetCurrentProcessId||!GetModuleFileNameW||!GetEnvironmentVariableW||!SetEnvironmentVariableW||!CreateFileW||!WriteFile||!CloseHandle||!CreateDirectoryW||!RemoveDirectoryW||!DeleteFileW||!CreateProcessW||!WaitForSingleObject||!GetCommandLineW||!ExitProcess||!g_LoadLibraryW) {
        if(ExitProcess) ExitProcess(2); for(;;){}
    }

    WCHAR* exePath=g_exePath; WCHAR* tempRoot=g_tempRoot; WCHAR* runDir=g_runDir; WCHAR* ps1Path=g_ps1Path; WCHAR* icoPath=g_icoPath; WCHAR* pngPath=g_pngPath; WCHAR* sysroot=g_sysroot; WCHAR* psExe=g_psExe; WCHAR* cmd=g_cmd;
    memzero(g_exePath,sizeof(g_exePath)); memzero(g_tempRoot,sizeof(g_tempRoot)); memzero(g_runDir,sizeof(g_runDir)); memzero(g_ps1Path,sizeof(g_ps1Path)); memzero(g_icoPath,sizeof(g_icoPath)); memzero(g_pngPath,sizeof(g_pngPath)); memzero(g_sysroot,sizeof(g_sysroot)); memzero(g_psExe,sizeof(g_psExe)); memzero(g_cmd,sizeof(g_cmd));

    if(!GetModuleFileNameW(NULL,exePath,2047)) { show_error(L"Не удалось определить путь к Keenetic Config Manager."); ExitProcess(3); }
    SetEnvironmentVariableW(L"KEENETIC_CONFIG_MANAGER_EXE",exePath);
    if(!GetTempPathW(1000,tempRoot)) { show_error(L"Не удалось получить временную папку Windows."); ExitProcess(4); }
    wcopy(runDir,tempRoot,1400); wappend(runDir,L"KeeneticConfigManager-2.1.0-Test1-",1400); wappend_dec(runDir,GetCurrentProcessId(),1400);
    CreateDirectoryW(runDir,NULL);
    wcopy(ps1Path,runDir,1800); wappend(ps1Path,L"\\Keenetic-Config-Manager.ps1",1800);
    wcopy(icoPath,runDir,1800); wappend(icoPath,L"\\Keenetic-Config-Manager.ico",1800);
    wcopy(pngPath,runDir,1800); wappend(pngPath,L"\\Keenetic-Config-Manager-Icon.png",1800);

    if(!write_blob(CreateFileW,WriteFile,CloseHandle,ps1Path,g_script,g_script_size)) { show_error(L"Не удалось распаковать встроенный PowerShell-код."); ExitProcess(5); }
    if(!write_blob(CreateFileW,WriteFile,CloseHandle,icoPath,g_icon,g_icon_size)) { DeleteFileW(ps1Path); show_error(L"Не удалось распаковать иконку приложения."); ExitProcess(6); }
    if(!write_blob(CreateFileW,WriteFile,CloseHandle,pngPath,g_png,g_png_size)) { DeleteFileW(ps1Path); DeleteFileW(icoPath); show_error(L"Не удалось распаковать PNG приложения."); ExitProcess(7); }

    DWORD sr=GetEnvironmentVariableW(L"SystemRoot",sysroot,1000);
    if(!sr || sr>=1000) wcopy(sysroot,L"C:\\Windows",1000);
    wcopy(psExe,sysroot,1600); wappend(psExe,L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",1600);

    wappend(cmd,L"\"",8192); wappend(cmd,psExe,8192); wappend(cmd,L"\" -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File \"",8192); wappend(cmd,ps1Path,8192); wappend(cmd,L"\"",8192);
    const WCHAR* rest=skip_first_arg(GetCommandLineW());
    if(rest && *rest) { wappend(cmd,L" ",8192); wappend(cmd,rest,8192); }

    STARTUPINFOW si; PROCESS_INFORMATION pi; memzero(&si,sizeof(si)); memzero(&pi,sizeof(pi)); si.cb=(DWORD)sizeof(si); si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    if(!CreateProcessW(psExe,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)) {
        DeleteFileW(ps1Path); DeleteFileW(icoPath); DeleteFileW(pngPath); RemoveDirectoryW(runDir);
        show_error(L"Не удалось запустить Windows PowerShell 5.1."); ExitProcess(8);
    }
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess,INFINITE);
    CloseHandle(pi.hProcess);
    DeleteFileW(ps1Path); DeleteFileW(icoPath); DeleteFileW(pngPath); RemoveDirectoryW(runDir);
    ExitProcess(0);
    for(;;){}
}
''';

c=prefix+arr('g_script',script)+arr('g_icon',ico)+arr('g_png',png)+suffix
Path(a.out).write_text(c,encoding='utf-8')
print(f'script={len(script)} ico={len(ico)} png={len(png)} c={len(c)} -> {a.out}')
