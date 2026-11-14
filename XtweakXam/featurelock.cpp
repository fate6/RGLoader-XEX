#include "stdafx.h"
#include "featurelock.h"
#include "utilities.h"
#include <stdio.h>
#include <string.h>
extern "C" void* _ReturnAddress(void);
#pragma intrinsic(_ReturnAddress)

#pragma warning (disable: 4996)

// xam 17489 (also what DevShadowBoot runs) and its kernel
#define ADDR_XamFeatureEnabled        0x81747D20	// ordinal 512: BOOL (DWORD id)
#define ADDR_XamFeatureSetMask        0x81748330	// ordinal 514: HRESULT (ULONGLONG* mask, DWORD size)
#define ADDR_XamFeatureEnableDisable  0x817483A8	// (BOOL enable, DWORD id)
#define ORD_ExGetXConfigSetting       16
#define ORD_ExSetXConfigSetting       24
#define XCONFIG_CAT_DEVKIT            0xB
#define XCONFIG_DEVKIT_FEATURE_MASK   2

#define FL_STATE_FILE "Hdd:\\Filesystems\\featurelock.bin"
#define FL_LOG_FILE   "Hdd:\\Filesystems\\featurelock.log"

static ULONGLONG g_protect = 0;
static ULONGLONG g_spoof = 0;		// mask the guarded modules asked for
static BOOL g_spoofValid = FALSE;

// ---------------------------------------------------------------- logging (flushed by a worker)
#define FL_LOGMAX 0x2000
#define FL_SEENMAX 96
static char g_log[FL_LOGMAX];
static volatile LONG g_logLen = 0;
static volatile LONG g_logDirty = 0;
static DWORD g_seen[FL_SEENMAX];
static volatile LONG g_seenCount = 0;
static RTL_CRITICAL_SECTION g_lock;

static void FlLog(const char* fmt, ...)
{
	char line[200];
	va_list va;
	va_start(va, fmt);
	int n = _vsnprintf(line, sizeof(line) - 3, fmt, va);
	va_end(va);
	if (n < 0) n = sizeof(line) - 3;
	line[n++] = '\r'; line[n++] = '\n'; line[n] = 0;
	RtlEnterCriticalSection(&g_lock);
	if (g_logLen + n < FL_LOGMAX) {
		memcpy(g_log + g_logLen, line, n);
		g_logLen += n;
		g_logDirty = 1;
	}
	RtlLeaveCriticalSection(&g_lock);
}

// Logs (function, caller) the first time it is seen.
static BOOL FlFirstSeen(DWORD func, DWORD lr)
{
	DWORD key = (lr & 0x0FFFFFFF) | (func << 28);
	BOOL first = TRUE;
	RtlEnterCriticalSection(&g_lock);
	for (LONG i = 0; i < g_seenCount; i++)
		if (g_seen[i] == key) { first = FALSE; break; }
	if (first && g_seenCount < FL_SEENMAX) g_seen[g_seenCount++] = key;
	else if (first) first = FALSE;	// table full: stop logging new callers
	RtlLeaveCriticalSection(&g_lock);
	return first;
}

// ---------------------------------------------------------------- who is calling
// Names the module containing addr (BaseDllName, ASCII). Returns TRUE if found.
static BOOL FlModuleOf(DWORD addr, char* name, int nameLen)
{
	PLDR_DATA_TABLE_ENTRY head = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle("xboxkrnl.exe");
	if (head == NULL) return FALSE;
	PLDR_DATA_TABLE_ENTRY cur = head;
	int guard = 0;
	do {
		DWORD base = (DWORD)cur->ImageBase;
		DWORD size = cur->SizeOfFullImage ? cur->SizeOfFullImage : cur->SizeOfNtImage;
		if (addr >= base && addr < base + size) {
			int i = 0;
			if (cur->BaseDllName.Buffer != NULL)
				for (; i < nameLen - 1 && i < cur->BaseDllName.Length / 2; i++)
					name[i] = (char)cur->BaseDllName.Buffer[i];
			name[i] = 0;
			return TRUE;
		}
		cur = (PLDR_DATA_TABLE_ENTRY)cur->InLoadOrderLinks.Flink;
	} while (cur != NULL && cur != head && ++guard < 256);
	name[0] = 0;
	return FALSE;
}

static BOOL FlIsGuarded(const char* mod)
{
	return _strnicmp(mod, "xbGuard", 7) == 0;
}

static void FlWriteFile(const char* path, const void* data, DWORD len);
static void FlFlushLog(void);

// Called when a write is blocked. Saved right away: the caller may reboot straight after.
static void FlSetSpoof(ULONGLONG m)
{
	g_spoof = m;
	g_spoofValid = TRUE;
	FlWriteFile(FL_STATE_FILE, &m, sizeof(m));
	FlFlushLog();
}

// ---------------------------------------------------------------- hooks
VOID __declspec(naked) FlEnabledSave(VOID) { __asm { li r3, 461
	nop
	nop
	nop
	nop
	nop
	nop
	blr } }
VOID __declspec(naked) FlSetMaskSave(VOID) { __asm { li r3, 462
	nop
	nop
	nop
	nop
	nop
	nop
	blr } }
VOID __declspec(naked) FlEnableDisableSave(VOID) { __asm { li r3, 463
	nop
	nop
	nop
	nop
	nop
	nop
	blr } }
VOID __declspec(naked) FlExGetSave(VOID) { __asm { li r3, 464
	nop
	nop
	nop
	nop
	nop
	nop
	blr } }
VOID __declspec(naked) FlExSetSave(VOID) { __asm { li r3, 465
	nop
	nop
	nop
	nop
	nop
	nop
	blr } }

typedef BOOL (*PFN_ENABLED)(DWORD id);
typedef HRESULT (*PFN_SETMASK)(ULONGLONG* mask, DWORD size);
typedef HRESULT (*PFN_ENABLEDISABLE)(BOOL enable, DWORD id);
typedef NTSTATUS (*PFN_EXGET)(WORD cat, WORD setting, PVOID buf, WORD size, PWORD retSize);
typedef NTSTATUS (*PFN_EXSET)(WORD cat, WORD setting, PVOID buf, WORD size);

static DWORD g_old[5][4];
static PFN_ENABLED g_enabledCall = NULL;	// the real XamFeatureEnabled (stub once hooked)

static ULONGLONG FlRealMask(void)
{
	ULONGLONG m = 0;
	for (DWORD id = 1; id <= 64; id++)
		if (g_enabledCall(id)) m |= 1ULL << (id - 1);
	return m;
}

static BOOL FlEnabledHook(DWORD id)
{
	DWORD lr = (DWORD)_ReturnAddress();
	BOOL real = ((PFN_ENABLED)FlEnabledSave)(id);
	if (lr >= 0x815F0000 && lr < 0x81EB0000)	// xam itself: hot path, never spoofed
		return real;
	char mod[24];
	FlModuleOf(lr, mod, sizeof(mod));
	BOOL ret = real;
	if (FlIsGuarded(mod) && g_spoofValid && id >= 1 && id <= 64)
		ret = (BOOL)((g_spoof >> (id - 1)) & 1);
	if (FlFirstSeen(1, lr))
		FlLog("XamFeatureEnabled(%u) from %08X %s -> real %d, returned %d", id, lr, mod, real, ret);
	return ret;
}

static HRESULT FlSetMaskHook(ULONGLONG* mask, DWORD size)
{
	DWORD lr = (DWORD)_ReturnAddress();
	char mod[24];
	FlModuleOf(lr, mod, sizeof(mod));
	if (mask != NULL && size == 8 && (g_protect & ~*mask) != 0) {
		// Apply the rest of the change, keeping the protected features on.
		ULONGLONG keep = *mask | g_protect;
		FlLog("XamFeatureSetMask(0x%I64X) from %08X %s kept 0x%I64X on, wrote 0x%I64X",
			*mask, lr, mod, g_protect & ~*mask, keep);
		FlSetSpoof(*mask);
		return ((PFN_SETMASK)FlSetMaskSave)(&keep, size);
	}
	FlLog("XamFeatureSetMask(0x%I64X) from %08X %s allowed", mask ? *mask : 0, lr, mod);
	return ((PFN_SETMASK)FlSetMaskSave)(mask, size);
}

static HRESULT FlEnableDisableHook(BOOL enable, DWORD id)
{
	DWORD lr = (DWORD)_ReturnAddress();
	char mod[24];
	FlModuleOf(lr, mod, sizeof(mod));
	if (!enable && id >= 1 && id <= 64 && ((g_protect >> (id - 1)) & 1)) {
		FlLog("XamFeatureEnableDisable(off, %u) from %08X %s BLOCKED", id, lr, mod);
		FlSetSpoof((g_spoofValid ? g_spoof : FlRealMask()) & ~(1ULL << (id - 1)));
		return S_OK;
	}
	FlLog("XamFeatureEnableDisable(%d, %u) from %08X %s allowed", enable, id, lr, mod);
	return ((PFN_ENABLEDISABLE)FlEnableDisableSave)(enable, id);
}

// XConfig devkit setting 2 (16 bytes): [0] = mask >> 32, [1] = ~mask & 0x7F (console disable bits)
static ULONGLONG FlDecodeXConfig(const DWORD* v)
{
	return ((ULONGLONG)v[0] << 32) | (~v[1] & 0x7F);
}

static NTSTATUS FlExGetHook(WORD cat, WORD setting, PVOID buf, WORD size, PWORD retSize)
{
	DWORD lr = (DWORD)_ReturnAddress();
	NTSTATUS st = ((PFN_EXGET)FlExGetSave)(cat, setting, buf, size, retSize);
	if (cat != XCONFIG_CAT_DEVKIT || setting != XCONFIG_DEVKIT_FEATURE_MASK)
		return st;
	char mod[24];
	FlModuleOf(lr, mod, sizeof(mod));
	BOOL spoofed = FALSE;
	if (st >= 0 && buf != NULL && size >= 8 && FlIsGuarded(mod) && g_spoofValid) {
		DWORD* v = (DWORD*)buf;
		v[0] = (DWORD)(g_spoof >> 32);
		v[1] = (DWORD)(~g_spoof & 0x7F);
		spoofed = TRUE;
	}
	if (FlFirstSeen(2, lr))
		FlLog("ExGetXConfigSetting(0xB,2) from %08X %s -> %08X%s", lr, mod, st, spoofed ? " (spoofed)" : "");
	return st;
}

static NTSTATUS FlExSetHook(WORD cat, WORD setting, PVOID buf, WORD size)
{
	if (cat != XCONFIG_CAT_DEVKIT || setting != XCONFIG_DEVKIT_FEATURE_MASK || buf == NULL || size < 8)
		return ((PFN_EXSET)FlExSetSave)(cat, setting, buf, size);
	DWORD lr = (DWORD)_ReturnAddress();
	char mod[24];
	FlModuleOf(lr, mod, sizeof(mod));
	ULONGLONG req = FlDecodeXConfig((const DWORD*)buf);
	if ((g_protect & ~req) != 0) {
		ULONGLONG keep = req | g_protect;
		DWORD v[4];
		memcpy(v, buf, size < 16 ? size : 16);
		v[0] = (DWORD)(keep >> 32);
		v[1] = (DWORD)(~keep & 0x7F);
		FlLog("ExSetXConfigSetting(0xB,2 = 0x%I64X) from %08X %s kept 0x%I64X on, wrote 0x%I64X",
			req, lr, mod, g_protect & ~req, keep);
		FlSetSpoof(req);
		return ((PFN_EXSET)FlExSetSave)(cat, setting, v, size < 16 ? size : 16);
	}
	FlLog("ExSetXConfigSetting(0xB,2 = 0x%I64X) from %08X %s allowed", req, lr, mod);
	return ((PFN_EXSET)FlExSetSave)(cat, setting, buf, size);
}

// ---------------------------------------------------------------- worker: writes log + state
static void FlWriteFile(const char* path, const void* data, DWORD len)
{
	HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) return;
	DWORD w;
	WriteFile(h, data, len, &w, NULL);
	CloseHandle(h);
}

static void FlFlushLog(void)
{
	RtlEnterCriticalSection(&g_lock);
	g_logDirty = 0;
	FlWriteFile(FL_LOG_FILE, g_log, g_logLen);
	RtlLeaveCriticalSection(&g_lock);
}

static DWORD WINAPI FlWorker(LPVOID)
{
	for (;;) {
		Sleep(2000);
		if (g_logDirty)
			FlFlushLog();
	}
	return 0;
}

// ---------------------------------------------------------------- install
static BOOL FlCheck(PDWORD p, DWORD w0, DWORD w1)
{
	return p != NULL && p[0] == w0 && (w1 == 0 || p[1] == w1 || ((w1 & 0xFC000003) == 0x48000001 && (p[1] & 0xFC000003) == w1));
}

BOOL FeatureLock_Install(ULONGLONG protectMask)
{
	g_protect = protectMask;
	RtlInitializeCriticalSection(&g_lock);

	PDWORD fEnabled = (PDWORD)ADDR_XamFeatureEnabled;
	PDWORD fSetMask = (PDWORD)ADDR_XamFeatureSetMask;
	PDWORD fEnDis = (PDWORD)ADDR_XamFeatureEnableDisable;
	PDWORD fExGet = (PDWORD)resolveFunct("xboxkrnl.exe", ORD_ExGetXConfigSetting);
	PDWORD fExSet = (PDWORD)resolveFunct("xboxkrnl.exe", ORD_ExSetXConfigSetting);
	PDWORD xamEnabledExport = (PDWORD)resolveFunct("xam.xex", 512);
	PDWORD xamSetMaskExport = (PDWORD)resolveFunct("xam.xex", 514);

	// Exact xam 17489 code only; anything else is left alone.
	if (xamEnabledExport != fEnabled || xamSetMaskExport != fSetMask
		|| !FlCheck(fEnabled, 0x2B030040, 0x40990008)
		|| !FlCheck(fSetMask, 0x7D8802A6, 0x9181FFF8)
		|| !FlCheck(fEnDis, 0x7D8802A6, 0x48000001)
		|| !FlCheck(fExGet, 0x7D8802A6, 0x48000001)
		|| !FlCheck(fExSet, 0x7D8802A6, 0x48000001)) {
		RGLDbgPrint(" * Feature lock: xam/kernel code not recognised (xam 17489 only), skipping\n");
		return FALSE;
	}

	HANDLE h = CreateFileA(FL_STATE_FILE, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h != INVALID_HANDLE_VALUE) {
		ULONGLONG m; DWORD r = 0;
		if (ReadFile(h, &m, sizeof(m), &r, NULL) && r == sizeof(m)) { g_spoof = m; g_spoofValid = TRUE; }
		CloseHandle(h);
	}
	g_enabledCall = (PFN_ENABLED)fEnabled;
	FlLog("Feature lock on: protect 0x%I64X, real mask 0x%I64X, reported to xbGuard: %s0x%I64X",
		g_protect, FlRealMask(), g_spoofValid ? "" : "(none yet) ", g_spoof);

	// Saved mask should be what the guarded module asked for plus the protected features (so a
	// feature dropped from Feature_Lock goes back to what xbGuard wants). xam reads it at boot,
	// so a change takes effect from the next boot.
	ULONGLONG real = FlRealMask();
	ULONGLONG want = (g_spoofValid ? g_spoof : real) | g_protect;
	if (want != real) {
		ULONGLONG fixed = want;
		HRESULT hr = ((PFN_SETMASK)fSetMask)(&fixed, 8);
		if (!g_spoofValid) FlSetSpoof(real);
		FlLog("Saved mask 0x%I64X -> 0x%I64X (%08X), on from next boot", real, fixed, hr);
	}

	hookFunctionStart(fEnabled, (PDWORD)FlEnabledSave, g_old[0], (DWORD)FlEnabledHook);
	g_enabledCall = (PFN_ENABLED)FlEnabledSave;
	hookFunctionStart(fSetMask, (PDWORD)FlSetMaskSave, g_old[1], (DWORD)FlSetMaskHook);
	hookFunctionStart(fEnDis, (PDWORD)FlEnableDisableSave, g_old[2], (DWORD)FlEnableDisableHook);
	hookFunctionStart(fExGet, (PDWORD)FlExGetSave, g_old[3], (DWORD)FlExGetHook);
	hookFunctionStart(fExSet, (PDWORD)FlExSetSave, g_old[4], (DWORD)FlExSetHook);

	HANDLE th; DWORD tid;
	ExCreateThread(&th, 0x10000, &tid, (PVOID)XapiThreadStartup, (LPTHREAD_START_ROUTINE)FlWorker, NULL, 0x2);
	ResumeThread(th);
	CloseHandle(th);

	RGLDbgPrint(" * Feature lock on (protect 0x%I64X)\n", g_protect);
	return TRUE;
}
