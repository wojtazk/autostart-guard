/*
 * driver.c - Aniol stroz autostartu, etap 2: blokowanie w trybie jadra.
 *
 * Co robi:
 *   1. Rejestruje callback na tworzenie procesow (PsSetCreateProcessNotifyRoutineEx).
 *   2. Trzyma plaska liste sciezek do zablokowania, wgrywana z user mode przez IOCTL.
 *   3. W trybie ENFORCE ustawia CreationStatus = STATUS_ACCESS_DENIED, czyli
 *      proces nie wstaje.
 *
 * Czego NIE robi (swiadomie - to PoC na zajecia):
 *   - nie parsuje JSON-a ani nie czyta plikow z dysku (to robi warstwa user mode),
 *   - nie liczy hashy plikow,
 *   - nie weryfikuje, kto wgrywa reguly, poza domyslnym ACL urzadzenia.
 *
 * WAZNE: wymaga linkera /INTEGRITYCHECK. Bez flagi IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
 * w naglowku PE funkcja PsSetCreateProcessNotifyRoutineEx zwraca STATUS_ACCESS_DENIED.
 */

#include <ntddk.h>
#include "agctl.h"

 /* ------------------------------------------------------------------ *
  *  Logowanie
  * ------------------------------------------------------------------ */

  /* DPFLTR_ERROR_LEVEL jest domyslnie wypuszczany, wiec widac to w DebugView
   * (z wlaczonym "Capture Kernel") bez grzebania w maskach filtrow. */
#define AG_LOG(...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AutostartGuard] " __VA_ARGS__)

   /* ------------------------------------------------------------------ *
    *  Stan globalny
    * ------------------------------------------------------------------ */

static PDEVICE_OBJECT g_DeviceObject = NULL;
static BOOLEAN        g_CallbackRegistered = FALSE;
static BOOLEAN        g_SymlinkCreated = FALSE;

/* Chroni g_Rules i g_RuleCount. Callback tworzenia procesu dziala na
 * PASSIVE_LEVEL, wiec FAST_MUTEX jest tu w porzadku. */
static FAST_MUTEX     g_RuleLock;
static AG_RULE        g_Rules[AG_MAX_RULES];
static ULONG          g_RuleCount = 0;

static volatile LONG   g_Mode = AG_MODE_AUDIT;  /* bezpieczny domyslny tryb */
static volatile LONG64 g_Evaluated = 0;
static volatile LONG64 g_Matched = 0;
static volatile LONG64 g_Blocked = 0;

/*
 * Bezpiecznik. Zla regula w trybie ENFORCE (np. pasujaca do svchost.exe)
 * potrafi zabic sesje albo caly system. Te obrazy nie zostana zablokowane
 * nigdy, nawet jesli trafia w regule - zostanie tylko wpis w logu.
 */
static const PCWSTR g_ProtectedNames[] =
{
    L"smss.exe",     L"csrss.exe",   L"wininit.exe",  L"winlogon.exe",
    L"services.exe", L"lsass.exe",   L"svchost.exe",  L"explorer.exe",
    L"dwm.exe",      L"userinit.exe", L"fontdrvhost.exe", L"lsaiso.exe",
    L"conhost.exe",  L"sihost.exe",  L"logonui.exe",  L"dllhost.exe"
};

/* ------------------------------------------------------------------ *
 *  Deklaracje
 * ------------------------------------------------------------------ */

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     AgUnload;
DRIVER_DISPATCH   AgCreateClose;
DRIVER_DISPATCH   AgDeviceControl;

static VOID AgCreateProcessNotify(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

/* ------------------------------------------------------------------ *
 *  Pomocnicze operacje na stringach
 * ------------------------------------------------------------------ */

/*
 * Czy 'full' konczy sie na 'suffix' (bez czulosci na wielkosc liter).
 */
static BOOLEAN AgEndsWithI(_In_ PCUNICODE_STRING full, _In_ PCUNICODE_STRING suffix)
{
    UNICODE_STRING tail;

    if (suffix->Length == 0 || suffix->Length > full->Length)
    {
        return FALSE;
    }

    tail.Buffer = (PWCH)((PUCHAR)full->Buffer + (full->Length - suffix->Length));
    tail.Length = suffix->Length;
    tail.MaximumLength = suffix->Length;

    return RtlEqualUnicodeString(&tail, suffix, TRUE);
}

/*
 * Wyciaga ostatni segment sciezki (sama nazwe pliku). Nie kopiuje -
 * zwrocony UNICODE_STRING wskazuje w bufor wejsciowy.
 */
static VOID AgGetLeafName(_In_ PCUNICODE_STRING path, _Out_ PUNICODE_STRING leaf)
{
    USHORT chars = (USHORT)(path->Length / sizeof(WCHAR));
    USHORT start = 0;
    USHORT i;

    for (i = 0; i < chars; i++)
    {
        if (path->Buffer[i] == L'\\')
        {
            start = (USHORT)(i + 1);
        }
    }

    leaf->Buffer = path->Buffer + start;
    leaf->Length = (USHORT)((chars - start) * sizeof(WCHAR));
    leaf->MaximumLength = leaf->Length;
}

/*
 * Czy obraz jest na liscie krytycznych procesow systemowych.
 */
static BOOLEAN AgIsProtectedImage(_In_ PCUNICODE_STRING imagePath)
{
    UNICODE_STRING leaf;
    UNICODE_STRING candidate;
    ULONG i;

    AgGetLeafName(imagePath, &leaf);

    for (i = 0; i < RTL_NUMBER_OF(g_ProtectedNames); i++)
    {
        RtlInitUnicodeString(&candidate, g_ProtectedNames[i]);
        if (RtlEqualUnicodeString(&leaf, &candidate, TRUE))
        {
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * Sprawdza sciezke obrazu wzgledem listy regul.
 * Zwraca indeks trafionej reguly albo -1.
 * Wywolywac z zalozonym g_RuleLock.
 */
static LONG AgFindMatchingRule(_In_ PCUNICODE_STRING imagePath)
{
    ULONG i;

    for (i = 0; i < g_RuleCount; i++)
    {
        PCWSTR raw = g_Rules[i].Path;
        UNICODE_STRING rule;

        /* Obcinamy litere dysku ("C:"), bo kernel operuje na sciezkach NT. */
        if (raw[0] != UNICODE_NULL && raw[1] == L':')
        {
            raw += 2;
        }

        if (raw[0] == UNICODE_NULL)
        {
            continue;
        }

        RtlInitUnicodeString(&rule, raw);

        if (AgEndsWithI(imagePath, &rule))
        {
            return (LONG)i;
        }
    }

    return -1;
}

/* ------------------------------------------------------------------ *
 *  Callback tworzenia procesu
 * ------------------------------------------------------------------ */

static VOID AgCreateProcessNotify(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNICODE_STRING image;
    LONG  mode;
    LONG  ruleIndex;
    BOOLEAN protectedImage;

    UNREFERENCED_PARAMETER(Process);

    /* CreateInfo == NULL oznacza wyjscie procesu - nas interesuje tylko start. */
    if (CreateInfo == NULL)
    {
        return;
    }

    if (CreateInfo->ImageFileName == NULL)
    {
        return;
    }

    mode = g_Mode;
    if (mode == AG_MODE_DISABLED)
    {
        return;
    }

    /* Bufor jest wazny tylko w czasie callbacku - kopiujemy sam deskryptor,
     * czytamy w miejscu, nic nie trzymamy na pozniej. */
    image = *CreateInfo->ImageFileName;

    InterlockedIncrement64(&g_Evaluated);

    ExAcquireFastMutex(&g_RuleLock);
    ruleIndex = AgFindMatchingRule(&image);
    ExReleaseFastMutex(&g_RuleLock);

    if (ruleIndex < 0)
    {
        return;
    }

    InterlockedIncrement64(&g_Matched);

    protectedImage = AgIsProtectedImage(&image);

    if (protectedImage)
    {
        AG_LOG("TRAFIENIE POMINIETE (proces systemowy) pid=%llu obraz=%wZ\n",
            (ULONG64)(ULONG_PTR)ProcessId, &image);
        return;
    }

    if (mode == AG_MODE_ENFORCE)
    {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        InterlockedIncrement64(&g_Blocked);

        AG_LOG("ZABLOKOWANO pid=%llu regula=%lu obraz=%wZ\n",
            (ULONG64)(ULONG_PTR)ProcessId, (ULONG)ruleIndex, &image);
    }
    else
    {
        AG_LOG("AUDYT (przepuszczono) pid=%llu regula=%lu obraz=%wZ\n",
            (ULONG64)(ULONG_PTR)ProcessId, (ULONG)ruleIndex, &image);
    }
}

/* ------------------------------------------------------------------ *
 *  Obsluga IRP
 * ------------------------------------------------------------------ */

_Use_decl_annotations_
NTSTATUS AgCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS AgDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS  status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    ULONG     inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG     outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID     buffer = Irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_AG_SET_MODE:
    {
        ULONG requested;

        if (inLen < sizeof(ULONG) || buffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        requested = *(PULONG)buffer;
        if (requested > AG_MODE_ENFORCE)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        InterlockedExchange(&g_Mode, (LONG)requested);
        AG_LOG("tryb ustawiony na %lu\n", requested);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_AG_CLEAR_RULES:
    {
        ExAcquireFastMutex(&g_RuleLock);
        RtlZeroMemory(g_Rules, sizeof(g_Rules));
        g_RuleCount = 0;
        ExReleaseFastMutex(&g_RuleLock);

        AG_LOG("lista regul wyczyszczona\n");
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_AG_ADD_RULE:
    {
        PAG_RULE incoming;

        if (inLen < sizeof(AG_RULE) || buffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        incoming = (PAG_RULE)buffer;

        /* Bufor przyszedl z user mode - wymuszamy zakonczenie NUL,
         * zeby zadna dalsza operacja na stringu nie wyjechala za bufor. */
        incoming->Path[AG_MAX_PATH - 1] = UNICODE_NULL;

        if (incoming->Path[0] == UNICODE_NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        ExAcquireFastMutex(&g_RuleLock);

        if (g_RuleCount >= AG_MAX_RULES)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            RtlCopyMemory(&g_Rules[g_RuleCount], incoming, sizeof(AG_RULE));
            g_RuleCount++;
            status = STATUS_SUCCESS;
        }

        ExReleaseFastMutex(&g_RuleLock);

        if (NT_SUCCESS(status))
        {
            AG_LOG("dodano regule: %ws\n", incoming->Path);
        }
        else
        {
            AG_LOG("odrzucono regule - limit %u osiagniety\n", AG_MAX_RULES);
        }
        break;
    }

    case IOCTL_AG_GET_STATS:
    {
        PAG_STATS stats;

        if (outLen < sizeof(AG_STATS) || buffer == NULL)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        stats = (PAG_STATS)buffer;

        ExAcquireFastMutex(&g_RuleLock);
        stats->RuleCount = g_RuleCount;
        ExReleaseFastMutex(&g_RuleLock);

        stats->Mode = (ULONG)g_Mode;
        stats->Evaluated = (ULONG64)InterlockedCompareExchange64(&g_Evaluated, 0, 0);
        stats->Matched = (ULONG64)InterlockedCompareExchange64(&g_Matched, 0, 0);
        stats->Blocked = (ULONG64)InterlockedCompareExchange64(&g_Blocked, 0, 0);

        information = sizeof(AG_STATS);
        status = STATUS_SUCCESS;
        break;
    }

    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

/* ------------------------------------------------------------------ *
 *  Zaladowanie / wyladowanie
 * ------------------------------------------------------------------ */

_Use_decl_annotations_
VOID AgUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlink;

    UNREFERENCED_PARAMETER(DriverObject);

    /* Kolejnosc ma znaczenie: najpierw odcinamy callback. Po powrocie z tego
     * wywolania gwarantowane jest, ze zaden callback nie jest w trakcie. */
    if (g_CallbackRegistered)
    {
        PsSetCreateProcessNotifyRoutineEx(AgCreateProcessNotify, TRUE);
        g_CallbackRegistered = FALSE;
    }

    if (g_SymlinkCreated)
    {
        RtlInitUnicodeString(&symlink, AG_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlink);
        g_SymlinkCreated = FALSE;
    }

    if (g_DeviceObject != NULL)
    {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    AG_LOG("wyladowany (przeanalizowano=%lld trafien=%lld zablokowano=%lld)\n",
        g_Evaluated, g_Matched, g_Blocked);
}

_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symlink;
    NTSTATUS       status;

    UNREFERENCED_PARAMETER(RegistryPath);

    AG_LOG("laduje sie\n");

    ExInitializeFastMutex(&g_RuleLock);
    RtlZeroMemory(g_Rules, sizeof(g_Rules));
    g_RuleCount = 0;

    DriverObject->DriverUnload = AgUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = AgCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = AgCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AgDeviceControl;

    RtlInitUnicodeString(&deviceName, AG_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,                      /* brak rozszerzenia urzadzenia - stan jest globalny */
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                  /* nie exclusive */
        &g_DeviceObject);

    if (!NT_SUCCESS(status))
    {
        AG_LOG("IoCreateDevice nie powiodlo sie: 0x%08X\n", status);
        return status;
    }

    RtlInitUnicodeString(&symlink, AG_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlink, &deviceName);

    if (!NT_SUCCESS(status))
    {
        AG_LOG("IoCreateSymbolicLink nie powiodlo sie: 0x%08X\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }
    g_SymlinkCreated = TRUE;

    status = PsSetCreateProcessNotifyRoutineEx(AgCreateProcessNotify, FALSE);

    if (!NT_SUCCESS(status))
    {
        /* Najczestsza przyczyna: brak /INTEGRITYCHECK przy linkowaniu
         * albo niepodpisany obraz -> STATUS_ACCESS_DENIED (0xC0000022). */
        AG_LOG("PsSetCreateProcessNotifyRoutineEx nie powiodlo sie: 0x%08X "
            "(sprawdz /INTEGRITYCHECK i podpis)\n", status);

        IoDeleteSymbolicLink(&symlink);
        g_SymlinkCreated = FALSE;
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }
    g_CallbackRegistered = TRUE;

    AG_LOG("gotowy - urzadzenie %ws, tryb startowy AUDIT\n", AG_SYMLINK_NAME);

    return STATUS_SUCCESS;
}
