#ifndef _HOPPER_ELF_H_
#define _HOPPER_ELF_H_

#include <elf.h>

#define ELF_LOAD_SUCCESS 0
#define ELF_LOAD_FAILURE -1

#define ELF_VALID 0
#define ELF_INVALID -1

#define SEG_FOUND 0
#define SEG_NOT_FOUND -1
#define SEG_INVALID -1

typedef struct {
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    FILE *handle;
    char *file_name;
} Elf64_FileInfo;

typedef struct {
    Elf64_Off offset;
    Elf64_Xword size;
    int index;
    char *old_name;
    char *new_name;
} Elf64_InterpInfo;

/* hopper.c functions */
void print_usage(const char *program_name);

/* utils.c functions */
int load_elf64_file(Elf64_FileInfo * fi);
int verify_target_binary(Elf64_Ehdr * ehdr);
int check_file_access(const char *file_path);
void print_flags(Elf64_Word p_flags);
void print_interps();

/* sym.c functions */
char *get_elf64_symbol_table(Elf64_FileInfo * fi);
void print_elf64_symbols(FILE * obj, Elf64_Shdr * shdr, long table_offset,
			 Elf64_Word type);

/* patch.c functions */
void patch_interpreter(Elf64_FileInfo * fi, Elf64_InterpInfo interpinfo);

/* seg.c functions */
Elf64_Phdr find_elf64_segment(Elf64_Ehdr ehdr, Elf64_Phdr * phdr,
			      uint32_t type);
int find_elf64_segment_index(Elf64_FileInfo * fi, uint32_t type);

#endif
