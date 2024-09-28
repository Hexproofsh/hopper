/* sym.c - part of the hopper toolkit to list symbol information for an
 * ELF64 binary.
 *
 *  (C) Copyright 2024 Travis Montoya "travgm" trav@hexproof.sh
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <stdlib.h>

#include "hopper_elf.h"

/* Returns the string table for an ELF64 binary */
char *get_elf64_symbol_table(Elf64_FileInfo * fi)
{
    if (fi == NULL || fi->handle == NULL) {
	return NULL;
    }

    /* Get the section headers table offset */
    fseek(fi->handle, fi->ehdr.e_shoff, SEEK_SET);
    fread(fi->shdr, sizeof(Elf64_Shdr), fi->ehdr.e_shnum, fi->handle);

    Elf64_Off table_offset = fi->shdr[fi->ehdr.e_shstrndx].sh_offset;
    char *shstrtab = malloc(fi->shdr[fi->ehdr.e_shstrndx].sh_size);
    if (shstrtab == NULL) {
	return NULL;
    }

    /* Seek to string table and read it into shstrtab */
    fseek(fi->handle, fi->shdr[fi->ehdr.e_shstrndx].sh_offset, SEEK_SET);
    fread(shstrtab, fi->shdr[fi->ehdr.e_shstrndx].sh_size, 1, fi->handle);

    return shstrtab;
}

/* Print symbols of type 'type' to stdout */
void
print_elf64_symbols (FILE * obj, Elf64_Shdr * shdr, long table_offset, Elf64_Word type)
{
    Elf64_Sym *sym = NULL;
    char symbol_name[256];
    int symbol_cnt = shdr->sh_size / sizeof(Elf64_Sym);
    int func_cnt = 0;

    sym = malloc(shdr->sh_size);

    fseek(obj, shdr->sh_offset, SEEK_SET);
    fread(sym, shdr->sh_size, 1, obj);
    for (int i = 0; i < symbol_cnt; i++) {
	/* if we are at the symbol with specified type print */
	if (ELF64_ST_TYPE(sym[i].st_info) == type) {
	    fseek(obj, table_offset + sym[i].st_name, SEEK_SET);
	    fgets(symbol_name, sizeof(symbol_name), obj);

	    printf("  %d: %016lx %s\n", func_cnt++, sym[i].st_value,
		   symbol_name);
	}
    }

    free(sym);
}
