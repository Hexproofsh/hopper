#ifndef _HOPPER_H_
#define _HOPPER_H_

#include <elf.h>

typedef struct
{
  Elf64_Off offset;
  Elf64_Xword size;
  int index;
  char *old_name;
  char *new_name;
} Elf64_InterpInfo;

/* hopper.c functions */
void print_usage (const char *program_name);

/* utils.c functions */
int verify_target_binary (Elf64_Ehdr * ehdr);
int check_file_access (const char *file_path);
void print_flags (Elf64_Word p_flags);
void print_interps ();

/* sym.c functions */
char * get_elf64_symbol_table (FILE * obj, Elf64_Ehdr ehdr, Elf64_Shdr * shdr);
void print_elf64_symbols (FILE * obj, Elf64_Shdr * shdr, long table_offset, Elf64_Word type);

/* patch.c functions */
void patch_interpreter (Elf64_Ehdr ehdr, Elf64_Phdr * phdr,
                        Elf64_InterpInfo interpinfo, FILE * obj);
#endif
