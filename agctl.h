/*
 * agctl.h - kontrakt miedzy driverem (kernel) a klientem (user mode).
 *
 * Projekt: Aniol stroz autostartu - etap 2 (blokowanie).
 *
 * Podzial odpowiedzialnosci:
 *   user mode  - czyta alerts/*.json, wyciaga targetPath, wysyla reguly tutaj
 *   kernel     - trzyma plaska liste regul i blokuje tworzenie procesow
 *
 * Driver NIE parsuje JSON-a i NIE czyta plikow. Tryb jadra dostaje gotowa,
 * zwalidowana liste sciezek.
 */

#pragma once

#ifndef AG_CTL_H
#define AG_CTL_H

/* ------------------------------------------------------------------ *
 *  Nazwy obiektow
 * ------------------------------------------------------------------ */

#define AG_DEVICE_NAME      L"\\Device\\AutostartGuard"
#define AG_SYMLINK_NAME     L"\\DosDevices\\AutostartGuard"
/* Z user mode otwierane jako: \\.\AutostartGuard */

/* ------------------------------------------------------------------ *
 *  Limity
 * ------------------------------------------------------------------ */

 /* Maksymalna liczba regul trzymanych jednoczesnie w driverze.
  * Tablica statyczna - zadnych alokacji w kernelu, zadnych wyciekow. */
#define AG_MAX_RULES        64

/* Dlugosc sciezki w regule (w znakach WCHAR, razem z NUL).
 * Dla dluzszych sciezek user mode moze podac sam ogon - dopasowanie
 * dziala na sufiksie (patrz AG_RULE ponizej). */
#define AG_MAX_PATH         260

/* ------------------------------------------------------------------ *
 *  Tryby pracy
 * ------------------------------------------------------------------ */

#define AG_MODE_DISABLED    0   /* callback nic nie robi */
#define AG_MODE_AUDIT       1   /* loguje trafienia, PUSZCZA proces (domyslny) */
#define AG_MODE_ENFORCE     2   /* loguje i BLOKUJE tworzenie procesu */

/* ------------------------------------------------------------------ *
 *  Struktury
 * ------------------------------------------------------------------ */

/*
 * Jedna regula blokujaca - sciezka do pliku wykonywalnego.
 *
 * Dopasowanie jest SUFIKSOWE i nieczule na wielkosc liter, bo kernel
 * widzi sciezke w formacie NT:
 *
 *   kernel:    \Device\HarddiskVolume3\Users\Public\svc_update.exe
 *   regula:    C:\Users\Public\svc_update.exe
 *
 * Driver obcina prefiks "C:" z reguly i sprawdza, czy sciezka z kernela
 * konczy sie na "\Users\Public\svc_update.exe". Skutek uboczny: regula
 * zawierajaca samo "svc_update.exe" zablokuje ten plik w KAZDYM katalogu.
 * To swiadoma decyzja - wygodne w PoC, ale trzeba o tym pamietac przy
 * budowaniu regul.
 */
typedef struct _AG_RULE
{
    WCHAR Path[AG_MAX_PATH];
} AG_RULE, * PAG_RULE;

/*
 * Licznik telemetrii - pozwala zademonstrowac dzialanie drivera bez
 * debuggera jadra (klient PowerShell wypisuje te liczby).
 */
typedef struct _AG_STATS
{
    unsigned long       Mode;         /* aktualny AG_MODE_* */
    unsigned long       RuleCount;    /* ile regul jest wgranych */
    unsigned long long  Evaluated;    /* ile tworzen procesu przeanalizowano */
    unsigned long long  Matched;      /* ile razy trafiono w regule */
    unsigned long long  Blocked;      /* ile razy faktycznie zablokowano */
} AG_STATS, * PAG_STATS;

/* ------------------------------------------------------------------ *
 *  Kody IOCTL
 * ------------------------------------------------------------------ */

#define AG_DEVICE_TYPE      0x8123

#ifndef CTL_CODE
/* Klient user mode dociaga CTL_CODE z <winioctl.h>. Gdy ktos wlaczy
 * ten header bez niego, podajemy wartosci wprost - patrz README. */
#define AG_CTL_CODE(fn, acc)  \
    ((AG_DEVICE_TYPE << 16) | ((acc) << 14) | ((fn) << 2) | 0 /* METHOD_BUFFERED */)
#define IOCTL_AG_SET_MODE       AG_CTL_CODE(0x800, 2)
#define IOCTL_AG_CLEAR_RULES    AG_CTL_CODE(0x801, 2)
#define IOCTL_AG_ADD_RULE       AG_CTL_CODE(0x802, 2)
#define IOCTL_AG_GET_STATS      AG_CTL_CODE(0x803, 1)
#else
/* FILE_WRITE_ACCESS na operacjach modyfikujacych = handle musi byc
 * otwarty z prawem zapisu. Domyslny deskryptor bezpieczenstwa urzadzenia
 * daje zapis tylko administratorom i SYSTEM, wiec zwykly user nie wgra
 * sobie regul. */
#define IOCTL_AG_SET_MODE \
    CTL_CODE(AG_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_AG_CLEAR_RULES \
    CTL_CODE(AG_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_AG_ADD_RULE \
    CTL_CODE(AG_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_AG_GET_STATS \
    CTL_CODE(AG_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)
#endif

#endif /* AG_CTL_H */
