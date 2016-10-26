
#include <jni.h>
#include <time.h>
#include <dlfcn.h>
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <android/log.h>
#include "TKHooklib.h"
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <setjmp.h>


//=====================================================================================================================
#define LOG_TAG "advancedLogging"
#define Debug_Log(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define CONFIG_FILE "/sdcard/libconfig.txt"
#define MAXLEN 80
#define TRY do{ jmp_buf ex_buf__; if( !setjmp(ex_buf__) ){
#define CATCH } else {
#define ETRY } }while(0)
#define THROW longjmp(ex_buf__, 1)
//=====================================================================================================================
void *pSubHandle;
void *pMonoHandle;
static void _libhook_init() __attribute__ ((constructor));
//=====================================================================================================================
struct dirent *hook_readdir(DIR *dirp);
struct dirent * (*orig_readdir)(DIR *dirp);

struct sample_parameters
{
//strstr working!
    char strstr[MAXLEN]; // log every time strstr called
//fopen working!
    char fopen[MAXLEN]; // log every time fopen called
//readdir work!
    char readdir[MAXLEN]; // log every time readdir called
//unlink working!
    char unlink[MAXLEN]; // log every time unlink called
//ptrace working!
    char ptrace[MAXLEN]; // log every time ptrace called
//open working!
    char open[MAXLEN]; // log every time open called
//prctl working!
    char prctl[MAXLEN]; // log every time prctl called
//mprotect working!
    char mprotect[MAXLEN]; // log every time mprotect called

    char dvmDefineClass[MAXLEN]; // log every time dvmDefineClass called

    char mono_image_open_from_data_with_name[MAXLEN]; // log every time mono_image_open_from_data_with_name called

    char kill[MAXLEN]; // log every time kill called
//strcpy working!
    char strcpy[MAXLEN]; // log every time strcpy called

    char dump_mmap[MAXLEN]; // log every time strcpy called

    char dump_mprotect[MAXLEN]; // log every time strcpy called

    char blockptrace[MAXLEN]; // log every time strcpy called

}
        sample_parameters;
/////////////////////////////////////////////////////////////////////////////////////////
// START Hooks
FILE *hook_fopen(const char *path, const char *mode);
FILE* (*orig_fopen)(const char *path, const char *mode);

int hook_unlink(const char *pathname);
int (*orig_unlink)(const char *pathname);

char * hook_strstr(const char *haystack, const char *needle);
char * (*orig_strstr)(const char *haystack, const char *needle);

char  hook_strcpy(char * str1, const char * str2);
char  (*orig_strcpy)(char * str1, const char * str2);

long hook_ptrace(int request, pid_t pid, void *addr, void *data);
long (*orig_ptrace)(int request, pid_t pid, void *addr, void *data);

int hook_open(const char *pathname, int flags);
int (*orig_open)(const char *pathname, int flags);

int hook_prctl(int option, long arg2, long arg3, long arg4, long arg5);
int (*orig_prctl)(int option, long arg2, long arg3, long arg4, long arg5);

int hook_mprotect(void *addr, size_t len, int prot);
int (*orig_mprotect)(void *addr, size_t len, int prot);

void hook_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void (*orig_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

int hook_kill(pid_t pid, int signum);
int (*orig_kill)(pid_t pid, int signum);

void hook_exit (int status);
void (*orig_exit)(int status);

// LibDVM Dump Dex - Working now
int hook_dvmDexFileOpenPartial(const void* addr, int len, void** ppDvmDex);
int (*orig_dvmDexFileOpenPartial)(const void* addr, int len, void** ppDvmDex);

int hook_dvmPrepareDexInMemory(const void* addr, int len, void** ppDvmDex);
int (*orig_dvmPrepareDexInMemory)(const void* addr, int len, void** ppDvmDex);

int hook_dvmDefineClass(void** pDvmDex, const char* descriptor, void** classLoader);
int (*orig_dvmDefineClass)(void** pDvmDex, const char* descriptor, void** classLoader);

// Mono Dump DLL
int hook_mono_image_open_from_data_with_name(const void *a1, size_t a2, int a3, int *a4, int a5, const char *a6);
int (*orig_mono_image_open_from_data_with_name)(const void *a1, size_t a2, int a3, int *a4, int a5, const char *a6);


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//CONFIG PARSING///////////////////////////////////////////////////////////////
char *
trim (char * s)
{
    /* Initialize start, end pointers */
    char *s1 = s, *s2 = &s[strlen (s) - 1];

    /* Trim and delimit right side */
    while ( (isspace (*s2)) && (s2 >= s1) )
        s2--;
    *(s2+1) = '\0';

    /* Trim left side */
    while ( (isspace (*s1)) && (s1 < s2) )
        s1++;

    /* Copy finished string */
    strcpy (s, s1);
    return s;
}

parse_config (struct sample_parameters * parms)
{
    char *s, buff[256];
    FILE *fp = fopen (CONFIG_FILE, "r");
    if (fp == NULL)
    {
        return 0;
    }

    /* Read next line */
    while ((s = fgets (buff, sizeof buff, fp)) != NULL)
    {
        /* Skip blank lines and comments */
        if (buff[0] == '\n' || buff[0] == '#')
            continue;

        /* Parse name/value pair from line */
        char name[MAXLEN], value[MAXLEN];
        s = strtok (buff, "=");
        if (s==NULL)
            continue;
        else
            strncpy (name, s, MAXLEN);
        s = strtok (NULL, "=");
        if (s==NULL)
            continue;
        else
            strncpy (value, s, MAXLEN);
        trim (value);

        /* Copy into correct entry in parameters struct */
        if (strcmp(name, "strstr")==0)
            strncpy (parms->strstr, value, MAXLEN);
        if (strcmp(name, "fopen")==0)
            strncpy (parms->fopen, value, MAXLEN);
        if (strcmp(name, "readdir")==0)
            strncpy (parms->readdir, value, MAXLEN);
        if (strcmp(name, "unlink")==0)
            strncpy (parms->unlink, value, MAXLEN);
        if (strcmp(name, "ptrace")==0)
            strncpy (parms->ptrace, value, MAXLEN);
        if (strcmp(name, "open")==0)
            strncpy (parms->open, value, MAXLEN);
        if (strcmp(name, "prctl")==0)
            strncpy (parms->prctl, value, MAXLEN);
        if (strcmp(name, "mprotect")==0)
            strncpy (parms->mprotect, value, MAXLEN);
        if (strcmp(name, "dvmDefineClass")==0)
            strncpy (parms->dvmDefineClass, value, MAXLEN);
        if (strcmp(name, "mono_image_open_from_data_with_name")==0)
            strncpy (parms->mono_image_open_from_data_with_name, value, MAXLEN);
        if (strcmp(name, "kill")==0)
            strncpy (parms->kill, value, MAXLEN);
        if (strcmp(name, "strcpy")==0)
            strncpy (parms->strcpy, value, MAXLEN);
        if (strcmp(name, "dump_mmap")==0)
            strncpy (parms->dump_mmap, value, MAXLEN);
        if (strcmp(name, "dump_mprotect")==0)
            strncpy (parms->dump_mprotect, value, MAXLEN);
        if (strcmp(name, "blockptrace")==0)
            strncpy (parms->blockptrace, value, MAXLEN);
            /*
        else
            printf ("WARNING: %s/%s: Unknown name/value pair!\n",
                    name, value);
            */
    }
    /* Close file */
    fclose (fp);
}
///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////
//=====================================================================================================================
static void _libhook_init()
{
    ///INIT STUFF
    struct sample_parameters parms;
    parse_config (&parms);


    Debug_Log("Loaded Hooks!\n");

    // Randomize
    srand(time(NULL));

    ///////////////////////////////////////////////////////////////////////////
    ///ART STUFF
/*
    void *libart = dlopen("libart.so", RTLD_LAZY);
    if (libart == NULL) {
        printf("Failed to load libdvm: %s\n", dlerror());
        return;
    }

    void *pFncDVMQ = (void *)dlsym(libart, "_ZN3art15DexFileVerifier13CheckListSizeEPKvjjPKc");
    if(!pFncDVMQ) {
        Debug_Log("dlsym dump_mmap failed");
        return;
    }
*/
    ///////////////////////////////////////////////////////////////////////////
    ///DVM STUFF
/*
    void *libdvm = dlopen("libdvm.so", RTLD_LAZY);
    if (libdvm == NULL) {
        printf("Failed to load libdvm: %s\n", dlerror());
        return;
    }

    void *pFncDVMP = (void *)dlsym(libdvm, "_Z21dump_mmapPhjPP6DvmDex");
    if(!pFncDVMP) {
        Debug_Log("dlsym dump_mmap failed");
        return;
    }

    void *pFncDVM = (void *)dlsym(libdvm, "_Z21dump_mprotectPKviPP6DvmDex");
    if(!pFncDVM) {
        Debug_Log("dlsym dump_mprotect failed");
        return;
    }



    void *pFncDVMC = (void *)dlsym(libdvm, "_Z14dvmDefineClassP6DvmDexPKcP6Object");
    if(!pFncDVMC) {
        Debug_Log("dlsym dvmDefineClass failed");
        return;
    }



    void *pFncDVME = (void *)dlsym(libdvm, "_Z22dvmGetCurrentJNIMethodv");
    if(!pFncDVME) {
        Debug_Log("dlsym dvmGetCurrentJNIMethod failed");
        return;
    }


    //hook_dvmDexSetResolvedClass(void** pDvmDex, unsigned int descriptor, void** ClassObject);
    void *pFncDVMD = (void *)dlsym(libdvm, "_Z22dvmDexSetResolvedClassP6DvmDexjP11ClassObject");
    if(!pFncDVMD) {
        Debug_Log("dlsym dvmDexSetResolvedClass failed");
        return;
    }
*/
    ///////////////////////////////////////////////////////////////////////////
    ///Mono STUFF
    pMonoHandle = dlopen("/data/data/org.raslin777.advancedLogging/lib/libmono.so", 0);
    if(pMonoHandle == 0) {
        Debug_Log("dlopen failed: %s", "/data/data/org.raslin777.advancedLogging/lib/libmono.so");
        return;
    }
    void *pFncMono = (void *)dlsym(pMonoHandle, "mono_image_open_from_data_with_name");
    if(!pFncMono) {
        Debug_Log("dlsym mono_image_open_from_data_with_name failed");
        return;
    }

    ///////////////////////////////////////////////////////////////////////////////////
    //Set Hooks//////////////////////////////////////////////////////////////////////////////
    pSubHandle = dlopen("/data/data/org.raslin777.advancedLogging/lib/libhooker.so", RTLD_NOW);
    if(pSubHandle == 0) {
        Debug_Log("dlopen failed: %s", "/data/data/org.raslin777.advancedLogging/lib/libhooker.so");
        return;
    }

    TK_InlineHookFunction_t pHookFunction;
    pHookFunction = (TK_InlineHookFunction_t)dlsym(pSubHandle, "TK_InlineHookFunction");
    if(pHookFunction == 0) {
        Debug_Log("dlsym TK_InlineHookFunction failed");
        return;
    }


    ////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////
    //SET HOOKS
    int result = 0;

    //FILE *fopen(const char *path, const char *mode);
    if (strcmp(parms.fopen, "1")==0){
        result = 0;
        Debug_Log("Patch fopen");
        result = pHookFunction(fopen, (void *)&hook_fopen, (void **)&orig_fopen);
        Debug_Log("Hooking fopen Result: %d", result);
    }

    //struct dirent *readdir(DIR *dirp);
    if (strcmp(parms.readdir, "1")==0){
        result = 0;
        Debug_Log("Patch readdir");
        result = pHookFunction(readdir, (void *)&hook_readdir, (void **)&orig_readdir);
        Debug_Log("Hooking readdir Result: %d", result);
    }

    //int unlink(const char *pathname);
    if (strcmp(parms.unlink, "1")==0){
        result = 0;
        Debug_Log("Patch unlink");
        result = pHookFunction(unlink, (void *)&hook_unlink, (void **)&orig_unlink);
        Debug_Log("Hooking unlink Result: %d", result);
    }

    //long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
    if (strcmp(parms.ptrace, "1")==0){
        result = 0;
        Debug_Log("Patch ptrace");
        result = pHookFunction(ptrace, (void *)&hook_ptrace, (void **)&orig_ptrace);
        Debug_Log("Hooking ptrace Result: %d", result);
    }

    //int open(const char *pathname, int flags);
    if (strcmp(parms.open, "1")==0){
        result = 0;
        Debug_Log("Patch open");
        result = pHookFunction(open, (void *)&hook_open, (void **)&orig_open);
        Debug_Log("Hooking open Result: %d", result);
    }

    //int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
    if (strcmp(parms.prctl, "1")==0){
        result = 0;
        Debug_Log("Patch prctl");
        result = pHookFunction(prctl, (void *)&hook_prctl, (void **)&orig_prctl);
        Debug_Log("Hooking prctl Result: %d", result);
    }

    //int mprotect(void *addr, size_t len, int prot);
    if (strcmp(parms.mprotect, "1")==0){
        result = 0;
        Debug_Log("Patch mprotect");
        result = pHookFunction(mprotect, (void *)&hook_mprotect, (void **)&orig_mprotect);
        Debug_Log("Hooking mprotect Result: %d", result);
        //result = 0;
        //Debug_Log("Patch mmap");
        //result = pHookFunction(mmap, (void *)&hook_mmap, (void **)&orig_mmap);
        //Debug_Log("Hooking mmap Result: %d", result);
    }
/*
    //bool dump_mmap(u1* addr, size_t len, DvmDex** ppDvmDex)
    if (strcmp(parms.dump_mmap, "1")==0){
        result = 0;
        Debug_Log("Patch dump_mmap");
        result = pHookFunction((void *)pFncDVMP, (void *)&hook_dump_mmap, (void **)&orig_dump_mmap);
        Debug_Log("Hooking dump_mmap Result: %d", result);
    }

    //int dump_mprotect(const void* addr, int len, DvmDex** ppDvmDex)
    if (strcmp(parms.dump_mprotect, "1")==0){
        result = 0;
        Debug_Log("Patch dump_mprotect");
        result = pHookFunction((void *)pFncDVM, (void *)&hook_dump_mprotect, (void **)&orig_dump_mprotect);
        Debug_Log("Hooking dump_mprotect Result: %d", result);
    }

    //ClassObject* dvmDefineClass(DvmDex* pDvmDex, const char* descriptor, Object* classLoader)
    if (strcmp(parms.dvmDefineClass, "1")==0){
        result = 0;
        Debug_Log("Patch dvmDefineClass");
        result = pHookFunction((void *)pFncDVMC, (void *)&hook_dvmDefineClass, (void **)&orig_dvmDefineClass);
        Debug_Log("Hooking dvmDefineClass Result: %d", result);
    }
*/
    //mono_image_open_from_data_with_name (char *data, uint32_t data_len, mono_bool need_copy, MonoImageOpenStatus *status, mono_bool refonly, const char *name);
    if (strcmp(parms.mono_image_open_from_data_with_name, "1")==0){
        result = 0;
        Debug_Log("Patch mono_image_open_from_data_with_name");
        result = pHookFunction((void *)pFncMono, (void *)&hook_mono_image_open_from_data_with_name, (void **)&orig_mono_image_open_from_data_with_name);
        Debug_Log("Hook mono Result: %d", result);
    }

    //char *strstr(const char *haystack, const char *needle);
    if (strcmp(parms.strstr, "1")==0){
        result = 0;
        Debug_Log("Patch strstr");
        result = pHookFunction(strstr, (void *)&hook_strstr, (void **)&orig_strstr);
        Debug_Log("Hooking strstr Result: %d", result);
    }

    //int kill(pid_t pid, int sig);
    if (strcmp(parms.kill, "1")==0){
        result = 0;
        Debug_Log("Patch kill");
        result = pHookFunction(kill, (void *)&hook_kill, (void **)&orig_kill);
        Debug_Log("Hooking kill Result: %d", result);
        result = 0;
        Debug_Log("Patch exit");
        result = pHookFunction(exit, (void *)&hook_exit, (void **)&orig_exit);
        Debug_Log("Hooking exit Result: %d", result);
    }

    //char *strcpy(char *dest, const char *src);
    if (strcmp(parms.strcpy, "1")==0){
        result = 0;
        Debug_Log("Patch strcpy");
        result = pHookFunction(strcpy, (void *)&hook_strcpy, (void **)&orig_strcpy);
        Debug_Log("Hooking strcpy Result: %d", result);
    }

}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//PATCHES HOOKS
//=====================================================================================================================
int hook_open(const char *pathname, int flags)
{
    if(pathname == NULL)
        return orig_open(pathname, flags);

    Debug_Log("open called ->: %s", pathname);
    /*
    if (pathname=="/data/data/com.joymobee.pocketmaplestory/files/AppEventsLogger.persistedevents")
    {
        Debug_Log("SLEEPNOW!");
        sleep(60);
    }
    */
    return orig_open(pathname, flags);
}
//=====================================================================================================================
int hook_prctl(int option, long arg2, long arg3, long arg4, long arg5)
{
    /*
    if(pathname == NULL)
        return orig_2open(pathname, flags, flags2);
    */
    Debug_Log("prctl called %i ",option);
    if (option==4)
    {
        //4
        Debug_Log("prctl called %i(PR_SET_DUMPABLE) Changing it to TRUE",option);
        arg2=1;
    }
    return orig_prctl(option, arg2, arg3, arg4, arg5);
}
//=====================================================================================================================
long hook_ptrace(int request, pid_t pid, void *addr, void *data)
{
    struct sample_parameters parms;
    parse_config (&parms);

    pid_t target_pid, ourpid, ourparent, ourleader;

    ourpid = getpid();
    ourparent = getppid();
    //ptrace(request, target_pid, addr, data);
    //request = 17;
    Debug_Log("*** self %d, parent %d, ***\n", ourpid, ourparent);
    Debug_Log("*** ptrace (%d, %x) ***\n", pid, request);
    Debug_Log("*** backtrace ***\n");

    //Needs cleanup
    if (strcmp(parms.blockptrace, "1")==0){

        if (ourpid != ourparent && ourparent == pid) {
            Debug_Log("*** bullshitting ***\n");
            return 0;}

    }

    return orig_ptrace(request, target_pid, addr, data);
    //return 0;
    //return orig_ptrace(request, pid, addr, data);
}
//=====================================================================================================================
char *randstring(int length) {
    char *string = "abcdefghijklmnopqrstuvwxyz0123456789";
    size_t stringLen = 35;
    char *randomString;

    randomString = malloc(sizeof(char) * (length +1));

    if (!randomString) {
        return (char*)0;
    }

    int n = 0;
    unsigned int key = 0;

    for (n = 0;n < length;n++) {
        key = rand() % stringLen;
        randomString[n] = string[key];
    }

    randomString[length] = '\0';

    return randomString;
}
//=====================================================================================================================
int hook_dvmPrepareDexInMemory(const void* addr, int len, void** ppDvmDex)
{
    Debug_Log("dvmPrepareDexInMemory Address: %p Length:%i", addr, len);
    return orig_dvmPrepareDexInMemory(addr, len, ppDvmDex);

}

//=====================================================================================================================

int hook_dvmDexFileOpenPartial(const void* addr, int len, void** ppDvmDex)
{
    Debug_Log("dvmDexFileOpenPartial Address:%p Length:%i", addr, len);

    char szOutFile[255];
    memset(szOutFile, 0, sizeof(szOutFile));

    // Get Rand String
    char *szFileName = randstring(5);
    if(!szFileName)
        return orig_dvmDexFileOpenPartial(addr, len, ppDvmDex);


    //Generate Random FileName
    strcpy(szOutFile, "/sdcard/");
    strcat(szOutFile, szFileName);
    strcat(szOutFile, ".dex");
    free(szFileName);

    // Write the Dex to Disk
    Debug_Log("Dumping Dex to %s - Size %d", szOutFile, len);
    FILE *file = fopen(szOutFile, "wb");
    if (file == NULL) {
        Debug_Log("Dex Problem, cant open: %s", szOutFile);
        return orig_dvmDexFileOpenPartial(addr, len, ppDvmDex);
    }
    fwrite(addr, 1, len, file);
    fclose(file);

    return orig_dvmDexFileOpenPartial(addr, len, ppDvmDex);

}

//=====================================================================================================================
int hook_mono_image_open_from_data_with_name(const void *a1, size_t a2, int a3, int *a4, int a5, const char *a6)
{
    // Init
    int i=0;
    int l=0;
    char *szBackSlash;
    char szOutFile[255];
    char *szFileName = strdup(a6);

    // Extract Filename
    szBackSlash = strstr(szFileName, "/");
    do{
        l = strlen(szBackSlash) + 1;
        szFileName = &szFileName[strlen(szFileName)-l+2];
        szBackSlash = strstr(szFileName, "/");
    }while(szBackSlash);

    memset(szOutFile, 0, sizeof(szOutFile));
    strcpy(szOutFile, "/sdcard/");
    strcat(szOutFile, szFileName);
    strcat(szOutFile, ".dec.dll");

    Debug_Log("Dumping: %s - Size %d - To: %s", szFileName, a2, szOutFile);

    FILE *file = fopen(szOutFile, "wb");
    if (file == NULL) {
        Debug_Log("Problem x 1");
        return orig_mono_image_open_from_data_with_name(a1, a2, a3, a4, a5, a6);
    }

    fwrite(a1, 1, a2, file);
    fclose(file);

    return orig_mono_image_open_from_data_with_name(a1, a2, a3, a4, a5, a6);
}
//=====================================================================================================================

int hook_dvmDefineClass(void** pDvmDex, const char* descriptor, void** classLoader)
{
    Debug_Log("dvmDefineClass: %s %p", descriptor, pDvmDex);
    return orig_dvmDefineClass(pDvmDex, descriptor, classLoader);
}
//=====================================================================================================================
void hook_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    //Debug_Log("mprotect called");
    struct sample_parameters parms;
    parse_config (&parms);

     if (strcmp(parms.dump_mmap, "1")==0){
    char szOutFile[255];
    memset(szOutFile, 0, sizeof(szOutFile));
    // Get Rand String
    char *szFileName = randstring(5);
    if(!szFileName)
        return orig_mmap(addr, length, prot, flags, fd, offset);
    //Generate Random FileName
    strcpy(szOutFile, "/sdcard/prodump/");
    strcat(szOutFile, szFileName);
    strcat(szOutFile, ".dex");
    free(szFileName);
    // Write the Dex to Disk
    Debug_Log("Dumping mprotect to %s - Size %d", szOutFile, length);
    FILE *file = fopen(szOutFile, "wb");
    if (file == NULL) {
        Debug_Log("Mprotect, cant open: %s", szOutFile);
        return orig_mmap(addr, length, prot, flags, fd, offset);
    }
    fwrite(addr, 1, length, file);
    fclose(file);
     }

    Debug_Log("MMAP, PROT_: %i", prot);

    return orig_mmap(addr, length, prot, flags, fd, offset);

}
//=====================================================================================================================
int hook_mprotect(void *addr, size_t len, int prot)
{
    //Debug_Log("mprotect called");
    struct sample_parameters parms;
    parse_config (&parms);

     if (strcmp(parms.dump_mprotect, "1")==0){

    char szOutFile[255];
    memset(szOutFile, 0, sizeof(szOutFile));
    // Get Rand String
    char *szFileName = randstring(5);
    if(!szFileName)
        return orig_mprotect(addr, len, prot);
    //Generate Random FileName
    strcpy(szOutFile, "/sdcard/prodump/");
    strcat(szOutFile, szFileName);
    strcat(szOutFile, ".dex");
    free(szFileName);
    // Write the Dex to Disk
    Debug_Log("Dumping mprotect to %s - Size %d", szOutFile, len);
    FILE *file = fopen(szOutFile, "wb");
    if (file == NULL) {
        Debug_Log("Mprotect, cant open: %s", szOutFile);
        return orig_mprotect(addr, len, prot);
    }
    fwrite(addr, 1, len, file);
    fclose(file);
     }

    Debug_Log("MPROTECT, PROT_: %i", prot);
    if (prot == 0) {
        Debug_Log("Mprotect, changing 0 to 1");
        prot = 1;
        return orig_mprotect(addr, len, prot);
    }

    return orig_mprotect(addr, len, prot);

}
//=====================================================================================================================

int IsHackFile(char *szFilename)
{
    return 0;
}
//=====================================================================================================================
char hook_strcpy(char *dst, const char *src)
{

    // Write the String to Disk
    /*
    FILE *file = fopen("/sdcard/list.strings", "ab+");
    if (file == NULL) {
        Debug_Log("String Problem, Cannot open: list.strings");
        return orig_strcpy(str1, str2);
    }
    fprintf(file, "String: %s\n", str2);
    fclose(file);
    */

    Debug_Log("strcpy: (%s)", src);
    char *ret = dst;
    while (*dst++ = *src++) ;
    return ret;
    //return orig_strcpy(str1, str2);
}
//=====================================================================================================================
char * hook_strstr(const char *haystack, const char *needle)
{
    Debug_Log("strstr: %s - %s", haystack, needle);
    return orig_strstr(haystack, needle);
}
//=====================================================================================================================
int hook_kill(pid_t pid, int signum)
{
    Debug_Log("KILL: %i", signum);
    return orig_kill(pid, signum);
}
//=====================================================================================================================
void hook_exit(int status)
{
    Debug_Log("exit: %i", status);
    return orig_exit(status);
}
//=====================================================================================================================
int hook_unlink(const char *pathname)
{
    Debug_Log("Unlink: %s", pathname);
    return 0;
}
//=====================================================================================================================
struct dirent *hook_readdir(DIR *dirp)
{
    struct dirent *dp = orig_readdir(dirp);

    if(dp)
    {
        Debug_Log("Readdir: %s", dp->d_name);

        while(IsHackFile(dp->d_name) == 1) {
            Debug_Log("Hack File Found -> Skipping");
            dp = orig_readdir(dirp);
            if(!dp)
                break;
            Debug_Log("Readdir: %s", dp->d_name);
        }
    }
    return dp;
}
//=====================================================================================================================#
FILE *hook_fopen(const char *path, const char *mode)
{
    if(path == NULL)
        return orig_fopen(path, mode);

    Debug_Log("fopen called ->: %s", path);
    return orig_fopen(path, mode);
}
//=====================================================================================================================