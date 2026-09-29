// Keenetic Config Manager single-EXE launcher helper (Windows x64, no CRT imports)
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef long LONG;
typedef int BOOL;
typedef unsigned long long QWORD;
typedef void* HANDLE;
typedef void* HMODULE;
typedef void* LPVOID;
typedef const void* LPCVOID;
typedef unsigned short WCHAR;
typedef WCHAR* LPWSTR;
typedef const WCHAR* LPCWSTR;
typedef char* LPSTR;
typedef const char* LPCSTR;
typedef DWORD* LPDWORD;

#define NULL ((void*)0)
#define FALSE 0
#define TRUE 1
#define GENERIC_WRITE 0x40000000UL
#define CREATE_ALWAYS 2UL
#define FILE_ATTRIBUTE_HIDDEN 0x00000002UL
#define FILE_ATTRIBUTE_TEMPORARY 0x00000100UL
#define CREATE_NO_WINDOW 0x08000000UL
#define STARTF_USESHOWWINDOW 0x00000001UL
#define SW_HIDE 0
#define INFINITE 0xFFFFFFFFUL
#define MB_ICONERROR 0x00000010UL
#define INVALID_HANDLE_VALUE ((HANDLE)(QWORD)(-1LL))

typedef struct _STARTUPINFOW {
    DWORD cb; LPWSTR lpReserved; LPWSTR lpDesktop; LPWSTR lpTitle;
    DWORD dwX; DWORD dwY; DWORD dwXSize; DWORD dwYSize;
    DWORD dwXCountChars; DWORD dwYCountChars; DWORD dwFillAttribute; DWORD dwFlags;
    WORD wShowWindow; WORD cbReserved2; BYTE* lpReserved2;
    HANDLE hStdInput; HANDLE hStdOutput; HANDLE hStdError;
} STARTUPINFOW;

typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess; HANDLE hThread; DWORD dwProcessId; DWORD dwThreadId;
} PROCESS_INFORMATION;

typedef DWORD (*PFN_GetTempPathW)(DWORD, LPWSTR);
typedef DWORD (*PFN_GetCurrentProcessId)(void);
typedef DWORD (*PFN_GetModuleFileNameW)(HMODULE, LPWSTR, DWORD);
typedef DWORD (*PFN_GetEnvironmentVariableW)(LPCWSTR, LPWSTR, DWORD);
typedef BOOL (*PFN_SetEnvironmentVariableW)(LPCWSTR, LPCWSTR);
typedef HANDLE (*PFN_CreateFileW)(LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE);
typedef BOOL (*PFN_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);
typedef BOOL (*PFN_CloseHandle)(HANDLE);
typedef BOOL (*PFN_CreateDirectoryW)(LPCWSTR, LPVOID);
typedef BOOL (*PFN_RemoveDirectoryW)(LPCWSTR);
typedef BOOL (*PFN_DeleteFileW)(LPCWSTR);
typedef BOOL (*PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCWSTR, STARTUPINFOW*, PROCESS_INFORMATION*);
typedef DWORD (*PFN_WaitForSingleObject)(HANDLE, DWORD);
typedef LPWSTR (*PFN_GetCommandLineW)(void);
typedef void (*PFN_ExitProcess)(DWORD);
typedef HMODULE (*PFN_LoadLibraryW)(LPCWSTR);
typedef int (*PFN_MessageBoxW)(HANDLE, LPCWSTR, LPCWSTR, unsigned int);

static void memzero(void* p, unsigned long n) { BYTE* b=(BYTE*)p; while(n--) *b++=0; }
static unsigned long cstrlen(const char* s) { unsigned long n=0; while(s && s[n]) n++; return n; }
static char alower(char c) { if(c>='A' && c<='Z') return (char)(c+('a'-'A')); return c; }
static WCHAR wlower(WCHAR c) { if(c>=L'A' && c<=L'Z') return (WCHAR)(c+(L'a'-L'A')); return c; }
static int ascii_eq(const char* a,const char* b){ while(*a&&*b){ if(*a!=*b)return 0; a++;b++; } return *a==*b; }

static void* get_peb(void) { void* p; __asm__("movq %%gs:0x60,%0" : "=r"(p)); return p; }

static void* find_module_ascii(const char* wanted) {
    BYTE* peb=(BYTE*)get_peb(); if(!peb) return NULL;
    BYTE* ldr=*(BYTE**)(peb+0x18); if(!ldr) return NULL;
    void** head=(void**)(ldr+0x20); void* cur=head[0]; unsigned long wn=cstrlen(wanted);
    while(cur && cur!=(void*)head) {
        BYTE* entry=(BYTE*)cur-0x10; WORD blen=*(WORD*)(entry+0x58); WCHAR* bname=*(WCHAR**)(entry+0x60);
        unsigned long chars=(unsigned long)(blen/2);
        if(bname && chars==wn) {
            unsigned long i; int ok=1;
            for(i=0;i<wn;i++) { WCHAR wc=wlower(bname[i]); char ac=alower(wanted[i]); if((WCHAR)(unsigned char)ac!=wc){ ok=0; break; } }
            if(ok) return *(void**)(entry+0x30);
        }
        cur=*(void**)cur;
    }
    return NULL;
}

static void* resolve_export(void* module,const char* name);
static void* resolve_forwarder(const char* fwd) {
    char mod[96]; char fun[160]; unsigned long i=0,j=0; int seenDot=0;
    while(fwd[i] && i<250) { if(!seenDot && fwd[i]=='.') { seenDot=1; i++; break; } if(j<90) mod[j++]=fwd[i]; i++; }
    mod[j]=0; j=0; while(fwd[i] && j<150) fun[j++]=fwd[i++]; fun[j]=0;
    if(!seenDot || !mod[0] || !fun[0] || fun[0]=='#') return NULL;
    unsigned long mn=cstrlen(mod); int hasdot=0; for(i=0;i<mn;i++) if(mod[i]=='.') hasdot=1;
    if(!hasdot && mn+4<sizeof(mod)) { mod[mn++]='.';mod[mn++]='d';mod[mn++]='l';mod[mn++]='l';mod[mn]=0; }
    void* target=find_module_ascii(mod); if(!target) return NULL; return resolve_export(target,fun);
}

static void* resolve_export(void* module,const char* name) {
    if(!module || !name) return NULL; BYTE* base=(BYTE*)module; if(*(WORD*)base != 0x5A4D) return NULL;
    DWORD peoff=*(DWORD*)(base+0x3c); BYTE* nt=base+peoff; if(*(DWORD*)nt != 0x00004550UL) return NULL;
    BYTE* opt=nt+24; if(*(WORD*)opt != 0x20b) return NULL;
    DWORD expRva=*(DWORD*)(opt+112); DWORD expSize=*(DWORD*)(opt+116); if(!expRva) return NULL;
    BYTE* ed=base+expRva; DWORD nNames=*(DWORD*)(ed+24); DWORD funcsRva=*(DWORD*)(ed+28);
    DWORD namesRva=*(DWORD*)(ed+32); DWORD ordsRva=*(DWORD*)(ed+36);
    DWORD* funcs=(DWORD*)(base+funcsRva); DWORD* names=(DWORD*)(base+namesRva); WORD* ords=(WORD*)(base+ordsRva);
    DWORD i; for(i=0;i<nNames;i++) {
        const char* en=(const char*)(base+names[i]);
        if(ascii_eq(en,name)) {
            DWORD rva=funcs[ords[i]];
            if(rva>=expRva && rva<expRva+expSize) return resolve_forwarder((const char*)(base+rva));
            return (void*)(base+rva);
        }
    }
    return NULL;
}

static unsigned long wlen(const WCHAR* s){ unsigned long n=0; while(s && s[n])n++; return n; }
static void wcopy(WCHAR* d,const WCHAR* s,unsigned long cap){ unsigned long i=0; if(!cap)return; while(s[i] && i+1<cap){d[i]=s[i];i++;}d[i]=0; }
static void wappend(WCHAR* d,const WCHAR* s,unsigned long cap){ unsigned long n=wlen(d),i=0; if(n>=cap)return; while(s[i] && n+1<cap){d[n++]=s[i++];}d[n]=0; }
static void wappend_dec(WCHAR* d,DWORD v,unsigned long cap){ WCHAR tmp[16]; unsigned long n=0,i; if(v==0){wappend(d,L"0",cap);return;} while(v && n<15){tmp[n++]=(WCHAR)(L'0'+(v%10));v/=10;} for(i=0;i<n;i++){ WCHAR one[2]; one[0]=tmp[n-1-i];one[1]=0;wappend(d,one,cap);} }

static const WCHAR* skip_first_arg(const WCHAR* cmd) {
    const WCHAR* p=cmd; if(!p) return L"";
    while(*p==L' '||*p==L'\t')p++;
    if(*p==L'"') { p++; while(*p && *p!=L'"')p++; if(*p==L'"')p++; }
    else { while(*p && *p!=L' ' && *p!=L'\t')p++; }
    while(*p==L' '||*p==L'\t')p++;
    return p;
}
