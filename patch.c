/* patch.c - patch the interpreter in elf64 binaries
 *
 *  usage: ./hopper [options(s)] [target]
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

#include "hopper.h"

void
patch_interpreter (Elf64_Ehdr ehdr, Elf64_Phdr * phdr,
                   Elf64_InterpInfo interpinfo, FILE * obj)
{
  printf ("Patching Binary:\n");
  printf ("  OLD 0x%lx:PT_INTERP = %s\n", interpinfo.offset,
          interpinfo.old_name);

  Elf64_Xword new_interp_len = strlen (interpinfo.new_name) + 1;

  fseek (obj, interpinfo.offset, SEEK_SET);
  fwrite (interpinfo.new_name, 1, new_interp_len, obj);

  phdr[interpinfo.index].p_filesz = new_interp_len;
  phdr[interpinfo.index].p_memsz = new_interp_len;

  fseek (obj, ehdr.e_phoff + interpinfo.index * sizeof (Elf64_Phdr),
         SEEK_SET);
  size_t b_written =
    fwrite (&phdr[interpinfo.index], sizeof (Elf64_Phdr), 1, obj);
  if (b_written > 0)
    {
      printf ("  NEW 0x%lx:PT_INTERP = %s\n", interpinfo.offset,
              interpinfo.new_name);
    }
}
