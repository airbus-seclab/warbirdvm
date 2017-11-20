/*
 *  (c) Copyright 2017 Airbus
 *  This file is part of warbirdvm/store and is released under GPLv2 (see warbirdvm/COPYING)
 *
 */

#define _WINSOCKAPI_

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KDEXT_64BIT
#include <wdbgexts.h>
#include <dbgeng.h>

#pragma warning(disable:4201) // nonstandard extension used : nameless struct


#ifdef __cplusplus
extern "C" {
#endif


#define INIT_API()                             \
    HRESULT Status;                            \
    if ((Status = ExtQuery(Client)) != S_OK) return Status;

#define EXT_RELEASE(Unk) \
    ((Unk) != NULL ? ((Unk)->Release(), (Unk) = NULL) : NULL)

#define EXIT_API     ExtRelease

// Extension information
#define EXT_MAJOR_VER    1
#define EXT_MINOR_VER    0

// Global variables initialized by query
extern PDEBUG_CLIENT4        g_ExtClient;
extern PDEBUG_CONTROL        g_ExtControl;
extern PDEBUG_SYMBOLS        g_ExtSymbols;
extern PDEBUG_SYMBOLS2       g_ExtSymbols2;
extern PDEBUG_SYMBOLS3       g_ExtSymbols3;
extern PDEBUG_REGISTERS      g_ExtRegisters;

extern ULONG64 g_Offset, g_Base;

HRESULT
ExtQuery(PDEBUG_CLIENT4 Client);

void
ExtRelease(void);

HRESULT
NotifyOnTargetAccessible(PDEBUG_CONTROL Control);

#ifdef __cplusplus
}
#endif
