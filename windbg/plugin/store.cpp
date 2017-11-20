/*
 *  (c) Copyright 2017 Airbus
 *  This file is part of warbirdvm/store and is released under GPLv2 (see warbirdvm/COPYING)
 *
 */

#include "store.h"
#include <strsafe.h>
#include <shlwapi.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

#define VERBOSE 0
#define STORE_SIZE 0x30

PDEBUG_CLIENT4          g_ExtClient;
PDEBUG_CONTROL          g_ExtControl;
PDEBUG_SYMBOLS          g_ExtSymbols;
PDEBUG_DATA_SPACES      g_ExtDataSpaces;
WINDBG_EXTENSION_APIS   ExtensionApis;

#define AES128KEYSIZE 16

BYTE g_AesKey[] = { 0x7f, 0xf9, 0x9b, 0xea, 0x82, 0x8c, 0x09, 0xfa, 0x8c, 0xa6, 0x46, 0x69, 0x2d, 0x4e, 0xd7, 0xa1};

typedef struct
{
    BLOBHEADER hdr;
    DWORD keySize;
    BYTE bytes[AES128KEYSIZE];
} AesKeyBlob;

static CHAR g_Store[STORE_SIZE];


// Queries for all debugger interfaces.
extern "C" HRESULT
ExtQuery(PDEBUG_CLIENT4 Client)
{
    HRESULT hRes=S_OK;

    if(g_ExtClient!=NULL)
        return S_OK;

    if (FAILED(hRes = Client->QueryInterface(__uuidof(IDebugControl), (void **)&g_ExtControl)))
        goto Fail;

    #if VERBOSE >= 2
    dprintf("[store] IDebugControl loaded\n");
    #endif

    if (FAILED(hRes = Client->QueryInterface(__uuidof(IDebugSymbols), (void **)&g_ExtSymbols)))
        goto Fail;

    #if VERBOSE >= 2
    dprintf("[store] IDebugSymbols loaded\n");
    #endif

    if (FAILED(hRes = Client->QueryInterface(__uuidof(IDebugDataSpaces), (void **)&g_ExtDataSpaces)))
        goto Fail;

    #if VERBOSE >= 2
    dprintf("[store] g_ExtDataSpaces loaded\n");
    #endif

    g_ExtClient = Client;
    return S_OK;

Fail:
    ExtRelease();
    return hRes;
}


// Cleans up all debugger interfaces.
void
ExtRelease(void)
{
    dprintf("[store] COM interfaces released\n");
    g_ExtClient = NULL;
    EXT_RELEASE(g_ExtControl);
    EXT_RELEASE(g_ExtSymbols);
    EXT_RELEASE(g_ExtDataSpaces);
}


extern "C"
HRESULT
CALLBACK
DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
    HRESULT hRes=S_OK;
    IDebugClient *DebugClient;
    PDEBUG_CONTROL DebugControl;

    *Version = DEBUG_EXTENSION_VERSION(EXT_MAJOR_VER, EXT_MINOR_VER);
    *Flags = 0;

    if (FAILED(hRes=DebugCreate(__uuidof(IDebugClient), (void **)&DebugClient)))
        return hRes;

    if (SUCCEEDED(hRes=DebugClient->QueryInterface(__uuidof(IDebugControl),  (void **)&DebugControl)))
    {
        // Get the windbg-style extension APIS
        ExtensionApis.nSize = sizeof (ExtensionApis);
        hRes = DebugControl->GetWindbgExtensionApis64(&ExtensionApis);
        DebugControl->Release();
        dprintf("[store] DebugExtensionInitialize, ExtensionApis loaded\n");
    }

    DebugClient->Release();
    return hRes;
}


extern "C"
void
CALLBACK
DebugExtensionUninitialize(void)
{
    dprintf("[store] DebugExtensionUninitialize\n");
    EXIT_API();
    return;
}


void DisplayStore()
{
    int i = 0;
    DWORD * ptr = (DWORD *)g_Store;
    DWORD dw1, dw2, dw3, dw4;

    dprintf("[store] DisplayStore :\n");

    for(i=0; i<(STORE_SIZE/0x10);i++)
    {
        dw1 = (DWORD) *(ptr);
        dw2 = (DWORD) *(ptr+0x1);
        dw3 = (DWORD) *(ptr+0x2);
        dw4 = (DWORD) *(ptr+0x3);
        dprintf("  > %p - 0x%08x 0x%08x 0x%08x 0x%08x\n", ptr, dw1, dw2, dw3, dw4);
        ptr += 0x4;
    }

}


HRESULT LoadStore()
{
    HRESULT hRes;
    ULONG BytesRead = 0;
    ULONG64 StorePtr=0, StoreAddr=0;

    hRes = g_ExtSymbols->GetOffsetByName("CI!g_pStore", &StorePtr);
    if (FAILED(hRes))
    {
        dprintf("[store] GetOffsetByName failed\n");
        goto Exit;
    }

    dprintf("[store] CI!g_pStore pointer address 0x%p\n", StorePtr);

    hRes = g_ExtDataSpaces->ReadPointersVirtual(1, StorePtr, &StoreAddr);
    if (FAILED(hRes))
    {
        dprintf("[store] ReadPointersVirtual failed\n");
        goto Exit;
    }

    dprintf("[store] CI!g_pStore  0x%p\n", StoreAddr);
    dprintf("[store] local Store  0x%p\n", g_Store);

    hRes = g_ExtDataSpaces->ReadVirtual(StoreAddr, (PVOID) g_Store, STORE_SIZE, &BytesRead);
    if (FAILED(hRes))
    {
        dprintf("[store] ReadVirtual failed, %x bytes read\n", BytesRead);
        goto Exit;
    }

Exit:
    return hRes;
}


HRESULT WriteStore()
{
    HRESULT hRes;
    ULONG BytesRead = 0;
    ULONG64 StorePtr=0, StoreAddr=0;

    hRes = g_ExtSymbols->GetOffsetByName("CI!g_pStore", &StorePtr);
    if (FAILED(hRes))
    {
        dprintf("[store] GetOffsetByName failed\n");
        goto Exit;
    }

    dprintf("[store] CI!g_pStore pointer address 0x%p\n", StorePtr);

    hRes = g_ExtDataSpaces->ReadPointersVirtual(1, StorePtr, &StoreAddr);
    if (FAILED(hRes))
    {
        dprintf("[store] ReadPointersVirtual failed\n");
        goto Exit;
    }

    dprintf("[store] CI!g_pStore  0x%p\n", StoreAddr);
    dprintf("[store] local Store  0x%p\n", g_Store);

    hRes = g_ExtDataSpaces->WriteVirtual(StoreAddr, (PVOID) g_Store, STORE_SIZE, &BytesRead);
    if (FAILED(hRes))
    {
        dprintf("[store] ReadVirtual failed, %x bytes read\n", BytesRead);
        goto Exit;
    }

Exit:
    return hRes;
}


HRESULT DecryptStore()
{
    HRESULT hRes=E_FAIL;
    BOOL bRes;
    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY  hKey       = NULL;
    DWORD Mode = CRYPT_MODE_ECB ;
    DWORD dwDataLen = 0x30;
    DWORD LastError;
    AesKeyBlob blob;

    dprintf("[store] DecryptStore\n");

    if (!(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)))
    {
        dprintf("[store] CryptAcquireContext failed\n");
        goto Exit;
    }

    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.reserved = 0;
    blob.hdr.aiKeyAlg = CALG_AES_128;
    blob.keySize = AES128KEYSIZE;

    memcpy(blob.bytes, g_AesKey, AES128KEYSIZE);

    if (!CryptImportKey(hCryptProv, (BYTE *)&blob, sizeof(AesKeyBlob), NULL, 0, &hKey))
    {
        dprintf("[store] CryptImportKey failed\n");
        goto Clean;
    }

    if (!(CryptSetKeyParam(hKey, KP_MODE, (const BYTE *)&Mode, NULL)))
    {
        dprintf("[store] CryptSetKeyParam failed\n");
        goto Clean;
    }

    if(!CryptDecrypt(hKey, 0, false, 0, (BYTE *)g_Store, &dwDataLen))
    {
        dprintf("[store] CryptDecrypt failed, 0x%08x\n", GetLastError());
    }

    CryptDestroyKey(hKey);
    hRes = S_OK;

Clean:
    CryptReleaseContext(hCryptProv,0);

Exit:
    return hRes;
}


HRESULT EncryptStore()
{
    HRESULT hRes=E_FAIL;
    BOOL bRes;
    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY  hKey       = NULL;
    DWORD Mode;
    DWORD dwDataLen = 0x30;
    DWORD LastError;
    AesKeyBlob blob;

    dprintf("[store] EncryptStore\n");

    if (!(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)))
    {
        dprintf("[store] CryptAcquireContext failed\n");
        goto Exit;
    }

    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.reserved = 0;
    blob.hdr.aiKeyAlg = CALG_AES_128;
    blob.keySize = AES128KEYSIZE;

    memcpy(blob.bytes, g_AesKey, AES128KEYSIZE);

    if (!CryptImportKey(hCryptProv, (BYTE *)&blob, sizeof(AesKeyBlob), NULL, 0, &hKey))
    {
        dprintf("[store] CryptImportKey failed\n");
        goto Clean;
    }

    Mode = CRYPT_MODE_ECB;
    if (!(CryptSetKeyParam(hKey, KP_MODE, (const BYTE *)&Mode, NULL)))
    {
        dprintf("[store] CryptSetKeyParam failed\n");
        goto Clean;
    }

    if(!CryptEncrypt(hKey, 0, false, 0, (BYTE *)g_Store, &dwDataLen, dwDataLen))
    {
        dprintf("[store] CryptDecrypt failed, 0x%08x\n", GetLastError());
    }

    CryptDestroyKey(hKey);
    hRes = S_OK;

Clean:
    CryptReleaseContext(hCryptProv,0);

Exit:
    return hRes;
}


HRESULT
CALLBACK
store_dump(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes=S_OK;
    PCSTR Host;
    PSTR pszId=NULL;
    INIT_API();

    hRes = LoadStore();
    if(FAILED(hRes))
    {
        dprintf("[store] LoadStore failed\n");
        goto Exit;
    }

    DisplayStore();

    hRes = DecryptStore();
    if(FAILED(hRes))
        dprintf("[store] DecryptStore failed\n");

	DisplayStore();

Exit:
    return hRes;
}


HRESULT
CALLBACK
store_setdw(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes=S_OK;
    ULONG RemainderIndex;
    DEBUG_VALUE DebugValue = {};
    DWORD Index, Value;
    DWORD * ptr = (DWORD *)g_Store;
    INIT_API();

    if (!Args || !*Args)
    {
        dprintf("[store] !store_setdw <Index> <Value>\n");
        goto Exit;
    }

    /*
    msdn: Evaluate method evaluates an expression, returning the result.
    */
    hRes=g_ExtControl->Evaluate(Args, DEBUG_VALUE_INT32, &DebugValue, &RemainderIndex);
    if(FAILED(hRes))
    {
        dprintf("[store] store_setdw: failed to evaluate module base\n");
        goto Exit;
    }

    Index = (DWORD)DebugValue.I32;
    if (Index > 0xB)
    {
        dprintf("[store] store_setdw: Index should be in 0..0xB\n");
        goto Exit;
    }

    Args += RemainderIndex;

    hRes=g_ExtControl->Evaluate(Args, DEBUG_VALUE_INT32, &DebugValue, &RemainderIndex);
    if(FAILED(hRes))
    {
        dprintf("[store] store_setdw: failed to evaluate dw Value\n");
        goto Exit;
    }

    Value = (ULONG64)DebugValue.I32;

    hRes = LoadStore();
    if(FAILED(hRes))
    {
        dprintf("[store] LoadStore failed\n");
        goto Exit;
    }

    hRes = DecryptStore();
    if(FAILED(hRes))
    {
        dprintf("[store] DecryptStore failed\n");
        goto Exit;
    }

    dprintf("[store] current store:\n");
    DisplayStore();

    // Patch store
    (DWORD) *(ptr+Index) = Value;

    dprintf("[store] new store:\n");
    DisplayStore();

    hRes = EncryptStore();
    if(FAILED(hRes))
    {
        dprintf("[store] EncryptStore failed\n");
        goto Exit;
    }

    hRes = WriteStore();
    if(FAILED(hRes))
    {
        dprintf("[store] WriteStore failed\n");
        goto Exit;
    }

Exit:
    return hRes;
}
