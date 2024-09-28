/* parser.c - full on parser functions
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

#define LINE_BREAK 18

int parse_elf64_obj_print_shellcode(Elf64_FileInfo * fi) {

    if (fi == NULL) {
	    return -1;
    }

    Elf64_SectionInfo sect_info = find_elf64_section_index(fi, SECTION_TEXT);
    if (sect_info.shdr_idx == SECTION_NOT_FOUND) {
	   printf("error: unable to find '%s' section\n", SECTION_NAME(SECTION_TEXT));
	   return SECTION_NOT_FOUND;
    }

    printf("Found '.text' section at 0x%016lx\n", sect_info.offset);

    unsigned char section_data[sect_info.size + 1];
    rewind(fi->handle);
    fseek(fi->handle, sect_info.offset, SEEK_SET);

    fgets(section_data, sect_info.size + 1, fi->handle);

    printf("\nShellcode:\n\t");
    int line = 0;
    int nulls = 0;
    for (int i = 0; i < sect_info.size; i++) {
	if (section_data[i] == 0) {
		nulls++;
	}
	if (line >= LINE_BREAK) {
		printf("\n\t");
		line = 0;
	}
        printf("\\x%02x", section_data[i]);
	line++;
    }

    printf("\n");
    if (nulls > 0) {
	printf("\nDetected %d null bytes in shellcode\n", nulls);
    }

    return 0;
}
