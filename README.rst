

Introduction
============

Our team recently had the opportunity to meet and exchange with two of the
authors of "**Rootkits and Bootkits, Reversing Modern Malware and Next
Generation Threats**" [1]_, namely Alex Matrosov and Eugene Rodionov, who
precisely are in the process of releasing the final edition of their textbook
(alongside with Sergey Bratus). Amongst all the knowledge they have packed
into their chapters, an old acquaintance reminds me of some researches I did a
few years ago on Windows 7 and Windows 8.1: ``ci.dll``.

``ci.dll`` is a cornerstone of Windows security and is involved very early in
its boot process. This module, and more specifically driver signature
enforcement code, got all the attention for obvious reasons (see [2]_). Still,
an unsung great piece of software engineering stayed hidden for too long
within its meanders: an encrypted memory store (``CI!g_pStore``), wrapped by
heavily obfuscated code using virtual-machine software protection and related
to a larger code protection framework: Microsoft Warbird.

The Warbird framework has gone relatively unnoticed for a long time, until
Alex Ionescu released "**The "Bird" That Killed Arbitrary Code Guard**" [3]_,
presented on September 27th 2017 at ekoparty conference in Buenos Aires. At
this occasion, it is deeply enlightening to discover how the Warbird framework
has evolved into a scary beast protecting from arbitrary code execution.


Many years have passed since our research and now seems a good time to
propose the following contributions:

* An analysis of the virtual-machine protection implemented in ``ci.dll`` on Windows 7/8.1
* A Windbg plugin performing on-the-fly decryption/encryption of the ``CI!g_pStore``


When the kernel whistles
========================

As a reminder, all the technical elements presented below have been studied on
Windows 7/8.1. From ``ci.dll``, one can easily locate the specific code by
looking for ``peauthvbn`` prefixed function names:

* ``peauthvbn_InitStore(x,x)``
* ``peauthvbn_GetDebugCredentialsData(x,x)``
* ``peauthvbn_GetBootDriversVerificationData(x,x)``
* ``peauthvbn_StoreParameter(x,x,x,x)``
* ``peauthvbn_GetParameters(x,x,x)``
* ``peauthvbn_SetDebugCredentialsData(x,x,x)``


These functions are all wrappers around the Warbird virtual machine. They are
used to initialize, query and update the ``CI!g_Store``. This store is
allocated in ``PEAuthInitStore`` and then initialized in
``peauthvbn_InitStore``. Please note that a random value issued from
``KETICKCOUNT`` is passed to the ``peauthvbn_InitStore`` function.


::

    int __stdcall PEAuthInitStore()
    {
      int seed;
      int res;
      PVOID allocated_store;
      MACRO_STATUS errno;

      seed = MEMORY[KETICKCOUNT];
      if ( g_Store )
        return STATUS_INVALID_PARAMETER;
      res = ExInitializeResourceLite(&g_StoreLock);
      if ( res >= 0 )
      {
        g_bStoreLockInitialized = 1;
        KeEnterCriticalRegion();
        ExAcquireResourceExclusiveLite(&g_StoreLock, 1u);
        allocated_store = ExAllocatePoolWithTag(PagedPool, sizeof(store), 'PE');
        g_Store = allocated_store;
        if ( allocated_store )
          errno = peauthvbn_InitStore(allocated_store, seed);
        else
          errno = STATUS_NO_MEMORY;
        ExReleaseResourceLite(&g_StoreLock);
        KeLeaveCriticalRegion();
        res = errno;
      }
      return res;
    }



::

    int __cdecl peauthvbn_InitStore(PVOID store_ptr, int seed)
    {
      return warbird_vm_internal(
               0xFAF1D7C599A70ADDi64,
               store_ptr,
               seed,
               0xFF9CAA0499D6ACBEi64,
               0xC31C4F59A8645793i64,
               0i64,
               0);
    }

``peauthvbn_InitStore`` invokes the virtual machine. The 64-bits values are
used to parametrize the execution of the virtual machine, like a keyed
execution. This key is stored in the ``rax`` native register and updated by
each of the 0x800 different handlers. When the updated value of the key is
zero, the execution of the virtual machine stops.


The execution loop of the virtual machine look like this:

::

    for ( ctx.field_90 = value; keyed_exec; keyed_exec = WARBIRD_HANDLERS[keyed_exec & 0x7FF](&ctx, keyed_exec) )



Warbird virtual machine
=======================

Not much needs to be said about the analysis of the virtual machine. By a
happy coincidence, the fifth chapter of the Practical Reverse Engineering
textbook contains a methodology that works like a charm to analyze the Warbird
virtual machine.

The core idea is simple: we unroll the execution of the virtual machine, using
static analysis and symbolic execution. In practice, we first lift the
function transfer of the current handler from its assembly code, then we
inject some symbolism into it (we know the virtual registers used by the
virtual machine are indexed based on rcx) and finally we perform a symbolic
execution of the result to step to the next handler and repeat these steps
until the execution ends.

The provided scripts are based on the Metasm framework [4]_, developed by Yoann
Guillot. They allow to statically unroll the execution of the virtual machine
and log each step.

* ``go.rb`` the launcher, it only passes a context to the symbolic execution engine.
* ``msvm64.rb``: the  core component, implements the handlers analysis and symbolic execution engine.
* ``aes.rb``: (spoiler alert) re-implementation of the ``peauthvbn_InitStore`` sub-program for debug purpose.

Let's illustrate the analysis methodology with the first handler executed when
``peauthvbn_InitStore`` is called. To begin with, at assembly level:

::

    PAGE:000000008005DAB8 sub_8005DAB8    proc near
    PAGE:000000008005DAB8 arg_0           = qword ptr  8
    PAGE:000000008005DAB8
    PAGE:000000008005DAB8    mov     [rsp+arg_0], rbx
    PAGE:000000008005DABD    mov     rbx, rcx
    PAGE:000000008005DAC0    mov     r11, rdx
    PAGE:000000008005DAC3    shr     r11, 20h
    PAGE:000000008005DAC7    mov     r10d, r11d
    PAGE:000000008005DACA    mov     r9d, r11d
    PAGE:000000008005DACD    sub     r10d, edx
    PAGE:000000008005DAD0    shl     edx, 4
    PAGE:000000008005DAD3    shr     r9d, 4
    PAGE:000000008005DAD7    add     r9d, edx
    PAGE:000000008005DADA    movzx   eax, r10b
    PAGE:000000008005DADE    xor     rax, 0A8h
    PAGE:000000008005DAE4    lea     edx, [r9+1788E3FCh]
    PAGE:000000008005DAEB    mov     r8, [rax+rcx]
    PAGE:000000008005DAEF    mov     rax, [rcx+78h]
    PAGE:000000008005DAF3    shl     rdx, 20h
    PAGE:000000008005DAF7    sub     rax, 28h
    PAGE:000000008005DAFB    mov     [rcx+1B8h], rax
    PAGE:000000008005DB02    lea     eax, [r11+6Dh]
    PAGE:000000008005DB06    movzx   ecx, al
    PAGE:000000008005DB09    movzx   eax, r9b
    PAGE:000000008005DB0D    xor     ecx, eax
    PAGE:000000008005DB0F    movzx   eax, r10b
    PAGE:000000008005DB13    xor     ecx, eax
    PAGE:000000008005DB15    lea     eax, [r11-5E99BF03h]
    PAGE:000000008005DB1C    sub     ecx, 96h
    PAGE:000000008005DB22    mov     [rcx+rbx], r8
    PAGE:000000008005DB26    mov     rbx, [rsp+arg_0]
    PAGE:000000008005DB2B    mov     ecx, r10d
    PAGE:000000008005DB2E    xor     rax, rcx
    PAGE:000000008005DB31    mov     ecx, 0D18DF8C6h
    PAGE:000000008005DB36    xor     rax, rcx
    PAGE:000000008005DB39    or      rax, rdx
    PAGE:000000008005DB3C    retn
    PAGE:000000008005DB3C sub_8005DAB8    endp


The code of the handlers is slightly obfuscated, some transformations are
applied on the data flow, however the control flow is clean.

Then we use Metasm to lift the function transfer of this piece of code (thanks
to the ``code_binding`` method from the disassembler object) and then replace
state pointers with symbolic variables:


::

    ---------------------------------------
    [+] (0) step with vmkey 0xfaf1d7c599a70add
    [+] analyzing handler 0x2dd at 0x8005dab8
    [+] new handler
    [+] eval_binding 8005dab8, finalize:true, complex:false
    [+] raw binding

    qword ptr [rsp+8] => rbx
    qword ptr [rcx+1b8h] => qword ptr [rcx+78h]-28h
    qword ptr [(((((((rdx>>20h)&0ffffffffh)+6dh)^((((rdx>>24h)&0fffffffh)+((rdx<<4)&0fffffff0h))^(((rdx>>20h)&0ffffffffh)-(rdx&0ffffffffh))))&0ffh)-96h)&0ffffffffh)+rcx] => qword ptr [(((((rdx>>20h)&0ffffffffh)-(rdx&0ffffffffh))^0a8h)&0ffh)+rcx]
    rax => (((((rdx>>20h)&0ffffffffh)+0ffffffffa16640fdh)^((((rdx>>20h)&0ffffffffh)-(rdx&0ffffffffh))^0d18df8c6h))&0ffffffffh)|(((((((rdx>>24h)&0fffffffh)+((rdx<<4)&0fffffff0h))&0ffffffffh)+1788e3fch)<<20h)&0ffffffff00000000h)

    [+] raw binding - rdx injected

    qword ptr [rcx+1b8h] => qword ptr [rcx+78h]-28h
    qword ptr [rcx] => qword ptr [rcx+40h]
    rax => 0c1a8af482c9f2cech

    [+] symbolic handler binding

    ctx_37 => ctx_f-28h
    ctx_0 => ctx_8
    rax => 0c1a8af482c9f2cech


This handler is fairly simple but others are more complex, with many registers
and/or memory assignments. In this example, two virtual registers are assigned
(``ctx_0`` and ``ctx37``) and of course the execution key of the virtual
machine is updated (``rax``).

As we said previously there are 0x800 of them, which most certainly indicates
they are generated programmatically. Most of them have a complex semantics, by
opposition to virtual machine designed to simply emulate a virtual processor
where each handler implements a simple instruction. In the Warbird virtual
machine, handlers are like chunks of the virtualized algorithm. Microsoft
developing the Warbird framework means they have full control over the source
code and the compilation tool-chain, thus we can expect this transformation
phase to be applied at compilation time.



Flipping tables
===============

We are now able to progress in the virtual machine code, trace a bunch of
handlers. Then, suddenly, everything goes mad. **SNAFU**: your statically
computed virtual context is trash compared to values you can observe using
dynamic analysis (debugging ``ci.dll``). This is due to a special attention
left for us by the developers of this protected code. Indeed, a few of the
handlers (less than 0x20/0x800) call a function that scrambles the context by
swapping some of its registers: ``ctx_scrambler``.

The ``code_binding`` method used to to lift the function transfer of the
handlers doesn't support sub-function calls. That why our analysis goes wrong.
We have to split the analysis and implement some extra magic.

Based on the value of the execution key, and some static data
(``scrambling_info``), ``ctx_scrambler`` applies permutations on the virtual
registers of the virtual machine.

::

    void __cdecl ctx_scrambler(VM_CTX *ctx, unsigned __int8 nb_round, __int64 scrambling_info)
    {
      _DWORD *scrambling_info_;
      unsigned int key;
      __int64 round;
      int scrambling_word;

      scrambling_info_ = (_DWORD *)scrambling_info;
      key = nb_round;
      if ( nb_round )
      {
        round = nb_round;
        do
        {
          scrambling_word = key ^ *scrambling_info_;
          ++scrambling_info_;
          key = scrambling_word + (8 * key ^ (key >> 3));
          *(&ctx->field_0 + BYTE1(scrambling_word)) = *(&ctx->field_0 + (unsigned __int8)scrambling_word);
          *(&ctx->field_0 + HIBYTE(scrambling_word)) = *(&ctx->field_0 + BYTE2(scrambling_word));
          --round;
        }
        while ( round );
      }
    }


Nothing we can't catch with our scripts, below is an example of scrambling
emulation, as it is emulated by the ``vm_ctx_scramble`` function:

::

    [+] key 0x37ed4b04
    [+] scramble word 0x2f86315
    [+] permutations word 0x35152811, ["11", "28", "15", "35"]
    [+]  ctx_28 = ctx_11
    [+]  ctx_35 = ctx_15
    [+] key 0xeead1951
    [+] scramble word 0xce8e0478
    [+] permutations word 0x20231d29, ["29", "1d", "23", "20"]
    [+]  ctx_1d = ctx_29
    [+]  ctx_20 = ctx_23
    [+] key 0x88e086cb
    [+] scramble word 0x8fd6aff9
    [+] permutations word 0x7362932, ["32", "29", "36", "7"]
    [+]  ctx_29 = ctx_32
    [+]  ctx_7 = ctx_36
    [+] key 0x5d4e4fb3
    [+] scramble word 0x4b457fbb
    [+] permutations word 0x160b3008, ["8", "30", "b", "16"]
    [+]  ctx_30 = ctx_8
    [+]  ctx_16 = ctx_b





Lifting the veil
================

Our analysis is now rock solid. We've been able to trace and log the execution
of all handlers involved in the ``peauthvbn_InitStore`` sub-program, to see how
the context of the virtual machine evolve, etc. The objective is now to get a
higher level understanding of what's going on.

There are a few techniques that can usually be used to break down complex
problems into smaller ones: trying to find loops, cycles, patterns, etc. This
can be applied successfully here as it looks like the complete trace can be
sub-divided into three similar looking chunks of 10 sub-chunks each.

Then, one can note that many handlers share a common pattern: they access a
table located in the data of the binary, ``LITTLE_BIRDS_TABLE``, to pick a
dword:


::

    ---------------------------------------
    [+] (7e) step with vmkey 0xa201ea87cb35977c
    [+] analyzing handler 0x77c at 0x8003f644
    [+] new handler
    [+] eval_binding 8003f644, finalize:true, complex:false

    [+] enable symbolic semantic
    [+] step semantic

    ctx_2d => ctx_27
    ctx_27 => (dword ptr [LITTLE_BIRDS_TABLE+4*((ctx_3+5eah)&0ffffffffh)]^0b0c9711bh)&0ffffffffh
    rax => 0cc006005e3c49cd2h

    [+] enable symbolic execution
    [+] final binding

    ctx_2d => 9fff38h
    ctx_27 => 15152a3fh
    rax => 0cc006005e3c49cd2h


When finding seemingly looking random values it is often a good idea to try to
match them with popular algorithms. Without spoiling all the fun, 0x15152a3f
is used in T-Table based implementation of the ``AES`` algorithm. With that
clue in mind we are close to solve the Warbird riddle.

We said that it is possible to split the complete trace into three similar
chunks. Each of these chunks independently updates 0x10 bytes of data (we got
this information from the log of the virtual machine).  Besides, the 10 (0xA)
sub-chunks are actually the rounds of the  ``AES`` algorithm , this leads us
to  an ``AES-128`` algorithm.

Then if we perform some additional dynamic tests, it appears that the chunks
of 0x10 bytes are encrypted independently. At the end, an educated guess would
be an ``AES-128-ECB`` algorithm (Electronic Codebook (``ECB``) encryption
mode).

Indeed, one can use its favorite cryptographic library to validate that the
``CI!g_pStore`` store  (0x30 bytes) is actually encrypted with the ``AES-128``
algorithm used in ``ECB`` mode.

Remember the random value passed to ``peauthvbn_InitStore``? It is stored in
the ``CI!g_pStore``, our guess is that its purpose is to diversify the
ciphertext (due to the use of the ``ECB`` mode).

We have the algorithm, now how do we get its key? The ``AES`` implementation
is actually a white-box implementation, meaning the key is hidden in the
implementation itself. For this iteration of Warbird, it is actually a very
basic white-boxing: the ``AES`` key stream is precomputed and hard-coded
within the handlers. One can extract the key from the key stream of the first
``AES`` round. See "**Practical cracking of white-box implementations**" from
SysK in Phrack issue 0x44 [5]_ for a good introduction.



Windbg plugin
=============

We have been able to recover the encryption algorithm and its key, at this
point we have all the details we need to inspect the ``CI!g_pStore`` on our
own. Let's pack all this in a Windbg script and start to dynamically  observe
the encrypted store of a debugged machine.

Please use the provided source code to build the ``store.dll``. It should then
be placed inside the ``winext`` directory of you Windbg package.

Then from Windbg, you'll be able to type:

::

    ************* Symbol Path validation summary **************
    Response                         Time (ms)     Location
    Deferred                                       srv*c:\symbols*http://msdl.microsoft.com/download/symbols
    Symbol search path is: srv*c:\symbols*http://msdl.microsoft.com/download/symbols
    Executable search path is:
    Windows 8.1 Kernel Version 9600 MP (1 procs) Free x64
    Built by: 9600.17936.amd64fre.winblue_ltsb.150715-0840
    Machine Name:
    Kernel base = 0xfffff800`ce871000 PsLoadedModuleList = 0xfffff800`ceb467b0
    System Uptime: 0 days 0:00:00.964

    nt!DbgBreakPointWithStatus:
    fffff800`ce9c7590 cc              int     3

    0: kd> .load store
    [store] DebugExtensionInitialize, ExtensionApis loaded

    0: kd> !store_dump
    [store] CI!g_pStore pointer address 0xfffff8018c158058
    [store] CI!g_pStore  0xffffc00102c09640
    [store] local Store  0x00007ff981115660
    [store] DisplayStore :
      > 00007ff981115660 - 0xf70853f7 0x97bbb404 0xd184fa8d 0xabf7dc7b
      > 00007ff981115670 - 0x2fd8b115 0xb76d6193 0x97a903ee 0xa6f229c0
      > 00007ff981115680 - 0xb95087b5 0xa50f6868 0xe4d47778 0xfbb05b87
    [store] DecryptStrore
    [store] DisplayStore :
      > 00007ff981115660 - 0x000003aa 0x00000000 0x00000001 0x00000000
      > 00007ff981115670 - 0x000003a9 0x00000000 0x00000003 0x00000000
      > 00007ff981115680 - 0x0000005b 0x00000000 0x00000000 0x00000000



Now let's say we want to modify some of the values stored in the store:

::

    0: kd> !store_setdw
    [store] !store_setdw <Index> <Value>

    0: kd> !store_setdw 1 8
    [store] CI!g_pStore pointer address 0xfffff8018c158058
    [store] CI!g_pStore  0xffffc00102c09640
    [store] local Store  0x00007ff981115660
    [store] DecryptStrore
    [store] current store:
    [store] DisplayStore :
      > 00007ff981115660 - 0x000003aa 0x00000000 0x00000001 0x00000000
      > 00007ff981115670 - 0x000003a9 0x00000000 0x00000003 0x00000000
      > 00007ff981115680 - 0x0000005b 0x00000000 0x00000000 0x00000000
    [store] new store:
    [store] DisplayStore :
      > 00007ff981115660 - 0x000003aa 0x00000008 0x00000001 0x00000000
      > 00007ff981115670 - 0x000003a9 0x00000000 0x00000003 0x00000000
      > 00007ff981115680 - 0x0000005b 0x00000000 0x00000000 0x00000000
    [store] EncryptStrore
    [store] CI!g_pStore pointer address 0xfffff8018c158058
    [store] CI!g_pStore  0xffffc00102c09640
    [store] local Store  0x00007ff981115660




Conclusion
==========

The tool-set proposed here is provided "as is", to possibly serve as a
background for future researches. The Warbird virtual machine analysis script
was developed a long time ago; it could be really interesting to see how more
recent frameworks like Miasm [6]_ or Triton [7]_ could help, especially as they
have both implemented a Dynamic Symbolic Execution (DSE) engine.

Few years ago, the simple idea of having an obfuscated, virtual machine based,
white-box ``AES`` in the Windows kernel was somehow unexpected to me.
Analyzing this beautifully crafted piece of software engineering has been
deeply inspiring. Besides it is just the tip of the iceberg; for example, more
could be said about its links with protected processes.

Since then, Alex Ionescu has demonstrated that Microsoft engineers have pushed
the Warbird framework to a totally new level in the most recent version of
Windows; broader in terms of scope, features and more complex than ever. Kudos
to them for that; for the rest of us it means that new challenges arise.

To conclude, thank you Alex & Eugene for the time we shared, we're looking
forward to the final edition!


A big thank you to the Airbus Digital Security team for their insightful
reviews and comments.



License
=======

The ``msvm`` tool and ``Store`` Windbg plugin are released under the [GPLv2]_.


.. [1] https://www.nostarch.com/rootkits
.. [2] http://j00ru.vexillium.org/?p=377
.. [3] https://www.ekoparty.org/charla.php?id=722
.. [4] https://github.com/jjyg/metasm
.. [5] http://phrack.org/issues/68/8.html#article
.. [6] https://github.com/cea-sec/miasm
.. [7] https://github.com/JonathanSalwan/Triton
.. [GPLv2] https://github.com/airbus-seclab/warbirdvm/blob/master/COPYING
