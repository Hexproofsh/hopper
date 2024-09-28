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

#include "hopper_elf.h"

/* Return the index into phdr of the segment 'type' */
int
find_elf64_segment_index(Elf64_FileInfo * fi, uint32_t type)
{
    for (int i = 0; i < fi->ehdr.e_phnum; i++) {
	if (fi->phdr[i].p_type == type) {
	    return i;
	}
    }
    return -1;
}
