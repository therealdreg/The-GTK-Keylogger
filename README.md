The GTK Keylogger by:

Abel Romero (aka D1W0U) @D1W0U, abel.romero@devopensource.com 

David Reguera (aka Dreg) @fr33project, dreg@fr33project.org 

--[ Table of contents

1. Introduction
2. Table of Keyloggers
3. How the GTK keylogger works
  3.1 The GTK+2 IM Contexts hooked
  3.2 The GTK+3 IM Contexts hooked
  3.3 The hooking technique
    3.3.1 The hook in x86
    3.3.2 The hook in x86_64
  3.4 Infection
  3.5 The problem with ld-config
4. Given support
5. How to test the GTK keylogger
6. Greetings
7. References
8. Appendix: code


--[ 1. Introduction

There're two scenarios that decides the content of a keylogger: the
execution space. They can be user-space or kernel-mode.

While an LKM keylogger depends on the version of the Linux Kernel and the
support to load modules, the most pieces of software for ring3 there're
public on Google are based on evdev.  Both have a problem that is about
translating the input of the user to visible characters, or better said to
characters there were really written.  Because the common scenario is to
catch scan codes, key codes and translate them to Unicode by getting and
combining the current keymap and lang. That process can be a pain in the
ass, but are the most used ways, what usually someone founds on Google by
quering "linux keylogger".

Also, those ways of keylogging shouldn't work to catch the virtual
keyboard, while our method allows to catch directly the Unicode,
automatically in the language that were written and whatever the input
method is installed and configured or by default.

If we do a leveled schema about what is more generic, at first we have the
known evdev keylogger, later the LKM one, and finally the GTK (or another
GUI library) keylogger. Because with evedev we read a device, which brings
us keycodes, with LKM we must take care about versions and support (but
those are usually supported and not hard to port), and in our keylogger we
depend on the binary code inside the libraries we hook. Because this method
is all about of hooking the right place, and catch the desired text.

There are more than one place in GTK were you can hook and catch data, but
there's only 1 place that supports virtual keyboard, any charset and all
the input methods. And finding those places were really hard even having
the source code, as the whole source code is based just in give support to
some platforms: openSUSE, Debian & Ubuntu, and some versions (the actual
when we developed it) of libgtk. Also, to catch special characteres there
are another places. And the most hard thing is that we had to do for the
two main versions of GTK available nowadays, which are v2 and v3.

Both are similar as they're a before release and a late one, but we must
say that in the latest one, the things are easier and better supported. For
example if we write in Arab inside the input text of a password field in
Firefox, we'll catch rubbish but that's because the v2 of GTK is not well
implemented for that, and finally it's better, because then the user must
use an ascii password and we won't catch false data as it won't login the
user, when writing a password in Arab.

In the v3, the things are all well supported, and we can catch every
Unicode character on any text input of the GTK applications.

We didn't gave support to Qt as the most supported is GTK, and even in KDE
we see that there aren't interesting applications where to catch
sensitive data. The most cool are coded with GTK, v2 or v3. That's the way
we did the GTK keylogger, because all we catch is what is seen on the
graphical applications, and those like Chrome, Chromium and Firefox are
handling the most sensitive data an user can work with.

A fail on our work, is that we can not catch KeePass passwords, because
that application is windows developed and ported to linux with some other
libraries different than GTK like libgdi. And as it was the only software
we found with those characteristics, we decided to finish our work by
giving full support to the versions in these days of GTK.


We must say that we developed this work for our job, we didn't spent a lot
of time in making our disassemblers/assemblers or a better infection method,
or persistence.

The true is that we are using capstone and keystone for this release, and a
very weak infection method, as we were doing it first functional and easy
to face development deadlines.  So, ofcourse there are better ways of doing
this, and maybe you are more expert than us.  We reconize that we are just
two researchers who decided to do this because we wanted that level of
keylogging and needed for our job, as I said, we are just showing you
another way of keylogging that is possible to do, and for sure some other
could do it better.  We want to share with you all our work and improve
that kind of tools, because we think it's very powerful.


--[ 2. Table of keyloggers

Here a table differentiating the kind of keyloggers we can use.

 Type           | Support           | Data             | Scope            |
----------------|-------------------|------------------|------------------|
Evdev keylogger | Completely generic| Catches keycodes | Keyboard events  |
----------------|-------------------|------------------|------------------|
LKM keylogger   | Semi generic      | Catches keycodes | All input events |
----------------|-------------------|------------------|------------------|
GTK keylogger   | Not generic       | Seen on GUI      | All using GTK    |
----------------|-------------------|------------------|------------------|


--[ 3. How the GTK keylogger works

First of all, we must patch the GTK shared object, making it to load ours.
Our shared object is the keylogger, that once loaded looks for the right
places where to hook, hooks and sets in the middle of the calls to those
functions.

It saves into a file in a path, selected at compilation time, all the data that
catches. Those are the log files. It differences between user ids, pids
and gids, to be safe and cleaner.

The method of hooking is thread-safe and is implemented both for x86 and
x86_64.

The reason because it's not generic, is due to the machine code is very
different in every version tested of v2, and the final implementation of
catching special characters in both versions.  Seems that the IM Contexts
are in development until the v3, were all the text is processed by the same
routine. Independently of the language, keymap or input method.

That requisite made us to do what I think is a well supported hooking,
having in mind that in future versions the machine code can change. So we
used a disassembler for C, called capstone, that helps us to identify
different opcodes before patch and then compose the correct hook code.


--[ 3.1 The GTK+2 IM Contexts hooked

There're two places where to hook, because some text is logged in one place
and other times, depending on the graphical control and language, is sent
by the other, in GTKv2. 

Text on method1: (EXPORTED) gtk_im_multicontext_set_context_id() ->
gtk_im_multicontext_set_slave() -> gtk_im_multicontext_commit_cb()

Special chars on method1: (EXPORTED) gtk_im_multicontext_new() ->
IA__gtk_im_multicontext_get_type() ->
gtk_im_multicontext_class_intern_init() ->
gtk_im_multicontext_filter_keypress()

Text on method2: (EXPORTED) gtk_im_context_simple_new() ->
IA__gtk_im_context_simple_get_type() ->
gtk_im_context_simple_class_intern_init() -> ->
gtk_im_context_simple_filter_keypress() ->
gtk_im_context_simple_commit_char()

Special chars on method2: (EXPORTED) gtk_im_context_simple_new() ->
IA__gtk_im_context_simple_get_type() ->
gtk_im_context_simple_class_intern_init() -> ->
gtk_im_context_simple_filter_keypress()


--[ 3.2 The GTK+3 IM Contexts hooked

On this version the IM Contexts are stable and better developed, everything
goes by one place and it's easier to do everything. So, making a keylogger
without special characters and only for GTK+3 would make the keylogger more
generic.

Unicode: (EXPORTED) gtk_im_multicontext_set_context_id() ->
gtk_im_multicontext_set_slave() -> gtk_im_multicontext_commit_cb()

Supporting special characters: (EXPORTED) gtk_im_multicontext_new() ->
IA__gtk_im_multicontext_get_type() ->
gtk_im_multicontext_class_intern_init() ->
gtk_im_multicontext_filter_keypress()


--[ 3.3 The hooking technique

We implemented hooking for x86 and x64, and it's decided on compilation
time.

The hooking method is based in three parts: routine patch, hook entry and
trampoline.


--[ 3.3.1 The hook in x86

The patch is done with push + ret and filled with nops.

The hook entry is basicaly a prolog and epilog that saves the registers and
the flags before calling the C handler. Same as x64 but easier.

It's located on the file `src/hook_entry_x86.S`.

The first call which is located in the function to hook, always is a call
to a function that moves to a register (ebx, eax, ecx, etc.) the value of
the retaddrr of the next instruction on that call, to make a trick of
rip-relative and be able to work with the following lea. So, we hardcoded
that instruction with a mov of the next address of the call.

The rest calls are rebuilded with a trick in ASM:

jmp _call
_push:
  push $addr_of__call
  ret
_call: call _push


As maybe you know, in x86_64 there're a difference from x86 when speaking
about pointing in code, which is called RIP relative addressing. That was
relatively easy to solve with capstone and the help of Dreg, but in x86 the
machine code is also using some RIP relative addressing, based on a call to
a function that just moves into a register the EIP and uses some other
register to point relatively to its value, as can be eax or any other.
What we did is explained in the section 3.3.1, and it's to get the EIP and
move it to the register that the routine is using in libgtk to simulate
that way of getting EIP into EAX, EBX, ECX or EDX that is used nowadays in
the x86 machine code of Linux.

Here you have a disassembly of some of the places we hook, in x86, with the
explained technique, and following the solution:

(gdb) disas gtk_im_multicontext_new
Dump of assembler code for function IA__gtk_im_multicontext_new:
   0x00109d10 <+0>: push   %ebx
   0x00109d11 <+1>: call   0x51730 <__x86.get_pc_thunk.bx>
   0x00109d16 <+6>: add    $0x3e82ea,%ebx

[...]

End of assembler dump.
(gdb) disas 0x51730
Dump of assembler code for function __x86.get_pc_thunk.bx:
   0x00051730 <+0>: mov    (%esp),%ebx
   0x00051733 <+3>: ret
End of assembler dump.

snprintf(asm_code,
  sizeof(asm_code),
  "mov %s, 0x%x",
  hardcoded_reg,
  (unsigned long) insn[i + 1].address);

printf("%s\n", asm_code);

asm_opcodes = Assemble(asm_code, &opcodes_sz);


--[ 3.3.2 The hook in x64

Patch of the routine to hook:

push rax
mov rax, ADDR_hook_entry
jmp rax
pop rax <-- ADDR return from
trampoline

The push rax it's used to keep the value of the rax, after the use of this
in the jmp to the hook entry.  The pop rax it's executed after the jmp from
the trampoline, because then we recover the value we had before.

The hook entry:

When we do pop rax and after a push of all the registers, we keep the rax.
And all the registers.

pop rax
pushfq
push REGISTERS
call handler_in_C
pop REGISTERS
popfq jmpq
TRAMPOLINE_ADDRESS

The trampoline in x64 rebuilds the lead, mov and push rip-relative.  And
has the following structure:

repaired_opcodes
push rax
mov rax, ADDR_return_from_trampoline
jmp rax


--[ 3.4 Infection

The idea is to load our shared-object on each GTK app, so the best idea for
keeping it user-space we found, is to patch the libgtk shared-object,
making it to load us on every load, because every GTK GUI loads this shared
object.

We found the tool patchelf in CPP which is on references, and we solved
this issue easily.

This tools what it does is to add a new NEEDED entry on the table in the
libgtk that the loader recognizes as a depdendency.  So as we did a
keylogger inside a shared-object, it adds our keylogger as a dependency of
gtk.

When the application loads gtk, gtk loads us. Then we are in the context of
the application.

PatchEFL can be found on GitHub and is on the references section.


--[ 3.5 The problem with ld-config

ld-config checks the integrity of each shared-object installed, so after
the call of ld-config, which is called for example on an upgrade, we can
see problematic messages of library integrity, that can advice the root
that something is wrong.

The solution is to patch ld-config, hook the function that advises, and do
a simple logic:

if (strcmp(library, "libgtk*") == 0) {
	// nothing to do :)
} else {
	// advise
}


--[ 4. Given support

The supported versions of libgtk+2 are: Ubuntu: 2.24.30-1ubuntu1,
2.24.30-4ubuntu2 and 2.24.30-4ubuntu3 Debian: 2.24.25-3+deb8u1 OpenSuse:
2.24.31-12.1

The operating systems were it was tested are: OpenSUSE x86_64, Debian 8
x86_64, Ubuntu 16.04 x86_64, Ubuntu 16.10 x86_64, Debian 8 x86 and Ubuntu
16.04 x86.

The applications on it was tested to work are: Thunderbird, Firefox,
Chrome, Chromiun, LibreOffice, GUI LOGIN, GEDIT, VeraCrypt, Skype, Pidgin,
Iceweasel, Terminal X.

The development was done in the GNOME environment, but it should work on
KDE applications that use GTK.

The languages tested were: Chineese (Pinyin way), Arab, English and
Spanish.  But it should work with any language.

The input methods tested were all offered by Ubuntu. It worked on everyone.

The virtual keyboard (florence) is logged also.


--[ 5. How-to test the GTK Keylogger

Extract from this paper, the compressed release and extract the release
also.

You should see a directory tree as the following:

drwxr-xr-x 11 diwou staff  352 Oct  4 12:55 .  drwxr-xr-x 68 diwou staff
2176 Oct  4 12:58 ..  -rw-r--r--  1 diwou staff 6148 Apr 17 12:59 .DS_Store
-rw-r--r--  1 diwou staff  689 Apr 17 13:00 Makefile.x64 -rw-r--r--  1
diwou staff  701 Apr 17 13:11 Makefile.x86 drwxr-xr-x  8 diwou staff  256
Apr 17 13:03 deps drwxr-xr-x  5 diwou staff  160 Apr 17 13:00 doc
drwxr-xr-x  7 diwou staff  224 Apr 17 13:00 include -rwxr-xr-x  1 diwou
staff 6321 Apr 17 14:16 install drwxr-xr-x  9 diwou staff  288 Oct  4 13:02
src -rwxr-xr-x  1 diwou staff 1384 Apr 17 13:00 uninstall

On a one of the supported operating systems listed before, and with the
supported libgtk installed, as root run the install script:

root@diwou-VirtualBox:~/shared_folder/ubuntu-x86# ./install Detected Linux
distribution is Ubuntu.  Installing deps ...  Leyendo lista de paquetes...
Hecho Creando árbol de dependencias       Leyendo la información de
estado... Hecho g++ ya está en su versión más reciente (4:5.3.1-1ubuntu1).
gcc ya está en su versión más reciente (4:5.3.1-1ubuntu1).  make ya está en
su versión más reciente (4.1-6).  cmake ya está en su versión más reciente
(3.5.1-1ubuntu3).  0 actualizados, 0 nuevos se instalarán, 0 para eliminar
y 391 no actualizados.  Please, enter a logging path [/tmp]: Compiling
Keylogger ...  gcc -I./include -c src/hook_entries_x86.S -o
src/hook_entries_x86.o
# uncomment for dev mode
#gcc -DKL_DEBUG -g -I./include -I./deps/capstone-3.0.5-rc2/include -Wall -o
libksutil-1.so.0 -shared -fPIC -ldl src/keylogger_shared_library.c
src/hook_entries_x86.o ./deps/capstone-3.0.5-rc2/libcapstone.a gcc
-I./include -I./deps/capstone-3.0.5-rc2/include -Wall -o libksutil-1.so.0
-shared -fPIC -ldl src/keylogger_shared_library.c src/hook_entries_x86.o
./deps/capstone-3.0.5-rc2/libcapstone.a src/keylogger_shared_library.c: In
function ‘HookGtkFunction’: src/keylogger_shared_library.c:1323:17:
warning: format ‘%x’ expects argument of type ‘unsigned int’, but argument
5 has type ‘long unsigned int’ [-Wformat=] "mov %s, 0x%x", ^
src/keylogger_shared_library.c:1323:17: warning: format ‘%x’ expects
argument of type ‘unsigned int’, but argument 5 has type ‘long unsigned
int’ [-Wformat=] g++ -o libasutil-1.so.0 src/kstool.cpp -Wall
-I./deps/keystone-0.9.1/include
./deps/keystone-0.9.1/build/llvm/lib/libkeystone.a done!

-------

Now the keylogger is installed.

Open an instance of Firefox for example, or a new terminal and write.

As you can see on the directory you choosed (/tmp for this case), there're
new .txt files.

diwou@diwou-VirtualBox:~/shared_folder/ubuntu-x86$ ls /tmp
config-err-gW7SKO
firefox.2595.2595.method1.log
firefox_diwou
systemd-private-c1ff4aea416542d38766daa829d3ec41-colord.service-IuWFjn
systemd-private-c1ff4aea416542d38766daa829d3ec41-rtkit-daemon.service-khr7wd
unity_support_test.1

diwou@diwou-VirtualBox:~/shared_folder/ubuntu-x86$ cat
/tmp/firefox.2595.2595.method1.log 
hotmai

phrack@hotmail.om

password

diwou@diwou-VirtualBox:~/shared_folder/ubuntu-x86$ od --width=10 -c
/tmp/firefox.2595.2595.method1.log 
0000000 357 273 277   g  \b  \b  \b  \b   h   o
0000012   t   m   a   i  \n  \n   p   h   r   a
0000024   c   k   @   h   o   t   m   a   i   l
0000036   .   c   m  \b  \b   o   m  \n  \n   p
0000050   a   s   s   w   o   r   d  \n
0000060
diwou@diwou-VirtualBox:~/shared_folder/ubuntu-x86$ 


To uninstall it just execute the uninstall script.

root@diwou-VirtualBox:~/shared_folder/ubuntu-x86# ./uninstall 
Uninstalling keylogger ...
done!


--[ 6. Greetings

Greetings to my brother LogicMan, to help me on my begginings and always
give me his support.


--[ 7. References

[1] https://nixos.org/patchelf.html 
[2] https://github.com/NixOS/patchelf
[3] https://www.cs.cmu.edu/afs/cs.cmu.edu/academic/class/15213-f03/www/ftrace/elf.c
[4] https://developer.gnome.org/gtk3/stable/gtk-building.html
[5] https://github.com/GNOME/gtk/tree/master
[6] https://developer.gnome.org/gtk3/stable/GtkIMContext.html#gtk-im-context-get-surrounding
[7] https://developer.gnome.org/pygtk/stable/class-gtkimcontextsimple.html
[8] https://developer.gnome.org/pygtk/stable/class-gtkimmulticontext.html
[10] https://github.com/GNOME/gtk/tree/gtk-2-0
[11] https://github.com/GNOME/gtk/blob/gtk-2-0/gtk/gtkimmulticontext.c
[12] https://github.com/GNOME/gtk/blob/gtk-2-0/gtk/gtkimcontextsimple.c
[13] https://github.com/GNOME/gtk/blob/gtk-3-0/gtk/gtkimmulticontext.c
[14] http://www.linuxquestions.org/questions/debian-26/dpkg-buildpackage-passing-configure-options-351791/
[15] https://github.com/kernc/logkeys 
[16] http://www.securitybydefault.com/2013/09/listado-de-keyloggers-windows-linux.html
[17] https://packetstormsecurity.com/files/87139/Nux-Keylogger-0.0.1.html
[18] https://sourceforge.net/projects/lkl/ 
[19] https://github.com/zacscott/zedlog 
[20] http://resources.infosecinstitute.com/keylogger/ 
[21] https://git.zx2c4.com/evdev-keylogger
[22] https://github.com/David-Reguera-Garcia-Dreg/libuiohook/tree/master/src/x11
