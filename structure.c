/* seg.c - patch the interpreter in elf64 binaries
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
#include <string.h>

#include "hopper_elf.h"

const char *section_name_strings[] = {
    [SECTION_TEXT] = ".text",
    [SECTION_DATA] = ".data",
    [SECTION_BSS] = ".bss",
    [SECTION_RODATA] = ".rodata",
    [SECTION_SYMTAB] = ".symtab",
    [SECTION_STRTAB] = ".strtab",
    [SECTION_REL_TEXT] = ".rel.text",
    [SECTION_RELA_TEXT] = ".rela.text",
    [SECTION_DEBUG] = ".debug",
    [SECTION_SHSTRTAB] = ".shstrtab",
    [SECTION_INIT] = ".init",
    [SECTION_FINI] = ".fini"
};

/* Return the index into phdr of the segment 'type' */
int find_elf64_segment_index(Elf64_FileInfo * fi, uint32_t type)
{
    for (int i = 0; i < fi->ehdr.e_phnum; i++) {
	if (fi->phdr[i].p_type == type) {
	    return i;
	}
    }
    return -1;
}

/* Searches for a section in a given ELF64 binary and returns an
 * Elf64_SectionInfo struct (Not an entire Shdr) info with some
 * other information we may need
 */
Elf64_SectionInfo find_elf64_section_index(Elf64_FileInfo * fi,
					   section_names section)
{
    Elf64_SectionInfo sect_info;
    sect_info.shdr_idx = -1;
    if (fi == NULL) {
	return sect_info;
    }

    char *shrstab = get_elf64_symbol_table(fi);
    for (int i = 0; i < fi->ehdr.e_shnum; i++) {
	Elf64_Word sect_str_off = fi->shdr[i].sh_name;

	const char *sec_name = shrstab + sect_str_off;
	if (strncmp(sec_name, SECTION_NAME(section), 5) == 0) {
	    sect_info.offset = fi->shdr[i].sh_offset;
	    sect_info.size = fi->shdr[i].sh_size;
	    sect_info.shdr_idx = i;
	    sect_info.section_name = strdup(sec_name);
	    break;
	}
    }

    return sect_info;
}
