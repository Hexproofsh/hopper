/* hopper.c - patch the interpreter in elf64 binaries
 *
 *  use make or compile:
 *  gcc -o hopper hopper.c
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
#include <stdbool.h>
#include <unistd.h>

#include "hopper.h"

/* Options for patching/displaying information */
bool verbose = false;
bool show_symbols = false;
bool disp_interp = false;

int
process_file (const char *file_name, const char *new_interp)
{
  Elf64_Ehdr ehdr;
  Elf64_Phdr *phdr = NULL;
  Elf64_Shdr *shdr = NULL;
  Elf64_Off table_offset = 0;
  Elf64_InterpInfo interpinfo;

  interpinfo.offset = 0;
  interpinfo.size = 0;
  interpinfo.index = 0;
  interpinfo.old_name = NULL;

  if (new_interp)
    {
      interpinfo.new_name = strdup (new_interp);
    }
  else
    {
      interpinfo.new_name = NULL;
    }

  FILE *obj = NULL;
  if ((obj = fopen (file_name, "r+b")) == NULL)
    {
      return -1;
    }

  fread (&ehdr, sizeof (ehdr), 1, obj);
  if (verify_target_binary (&ehdr) != 0)
    {
      fprintf (stderr,
	       "errror: not a valid dynamically linked ELF64 binary\n");
      return -1;
    }

  phdr = malloc (ehdr.e_phnum * sizeof (Elf64_Phdr));
  if (phdr == NULL)
    {
      fprintf (stderr, "error: unable to allocate memory for phdr\n");
      fclose (obj);
      return -1;
    }

  fseek (obj, ehdr.e_phoff, SEEK_SET);
  fread (phdr, sizeof (Elf64_Phdr), ehdr.e_phnum, obj);

  /* Find our PT_INTERP segment, this must exist to continue */
  for (int i = 0; i < ehdr.e_phnum; i++)
    {
      if (phdr[i].p_type == PT_INTERP)
	{
	  if (verbose)
	    {
	      printf ("Found PT_INTERP segment at 0x%016lx\n",
		      phdr[i].p_vaddr);
	      printf ("Offset: 0x%lx\n", phdr[i].p_offset);
	      printf ("Size: %zu\n", phdr[i].p_filesz);
	      print_flags (phdr[i].p_flags);
	    }
	  interpinfo.offset = phdr[i].p_offset;
	  interpinfo.size = (Elf64_Xword) phdr[i].p_filesz;
	  interpinfo.index = i;
	  break;
	}
    }

  if (interpinfo.offset == 0)
    {
      fprintf (stderr, "error: no PT_INTERP segment found\n");
      free (phdr);
      fclose (obj);
      return -1;
    }

  if (show_symbols)
    {
      Elf64_Shdr *shdr = malloc (ehdr.e_shnum * sizeof (Elf64_Shdr));
      if (shdr == NULL)
      {
	free (phdr);
	fclose (obj);
        return -1;
      }
      
      char *sym_table = get_elf64_symbol_table(obj, ehdr, shdr);
      if (sym_table == NULL) {
	      free (phdr);
	      fclose (obj);
	      return -1;
      }

      for (int i = 0; i < ehdr.e_shnum; i++)
	{
	  if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM)
	    {
	      const char *symtab_name = sym_table + shdr[i].sh_name;
	      printf ("Symbol Table '%s' (STT_FUNC):\n", symtab_name);
	      print_elf64_symbols (obj, &shdr[i], shdr[shdr[i].sh_link].sh_offset, STT_FUNC);
	    }
	}

      free (shdr);
      free (sym_table);
    }

  fseek (obj, interpinfo.offset, SEEK_SET);
  char *interp = malloc (interpinfo.size);
  if (interp == NULL)
    {
      free (phdr);
      free (shdr);
      fclose (obj);
      return -1;
    }

  size_t b_read = fread (interp, 1, interpinfo.size, obj);
  if (b_read != interpinfo.size)
    {
      free (interp);
      free (phdr);
      return -1;
    }

  interpinfo.old_name = interp;

  if (disp_interp)
    {
      printf ("0x%lx:PT_INTERP = %s\n", interpinfo.offset,
	      interpinfo.old_name);
    }

  if (interpinfo.new_name)
    {
      patch_interpreter (ehdr, phdr, interpinfo, obj);
    }

  free (interp);
  free (phdr);
  fclose (obj);

  return 0;

}

void
print_usage (const char *program_name)
{
  fprintf (stderr,
	   "Hopper the ELF64 PT_INTERP tool by Travis Montoya <trav@hexproof.sh>\n");
  fprintf (stderr, "usage: %s [option(s)] [target]\n", program_name);
  fprintf (stderr, "  -v                 show verbose output\n");
  fprintf (stderr,
	   "  -s                 display symbol information (STT_FUNC)\n");
  fprintf (stderr, "  -d                 display interpreter\n");
  fprintf (stderr, "  -p [interpreter]   patch interpreter\n");
  fprintf (stderr,
	   "\nYou can run '%s -search' to list common interpreters on your system\n",
	   program_name);
}

int
main (int argc, char *argv[])
{
  int opt;
  char *interp = NULL;
  char *target_elf = NULL;

  if (argc < 2)
    {
      print_usage (argv[0]);
      return 1;
    }

  /* If we are just searching do nothing further */
  if (argc == 2 && strncmp (argv[1], "-search", 7) == 0)
    {
      print_interps ();
      return 0;
    }

  while ((opt = getopt (argc, argv, "vsdp:")) != -1)
    {
      switch (opt)
	{
	case 'v':
	  verbose = true;
	  break;
	case 's':
	  show_symbols = true;
	  break;
	case 'd':
	  disp_interp = true;
	  break;
	case 'p':
	  interp = optarg;
	  break;
	default:
	  print_usage (argv[0]);
	  return 1;
	}
    }

  if (disp_interp && interp)
    {
      fprintf (stderr, "error: You cant patch and display the interpreter\n");
      return 1;
    }

  if (!disp_interp && !interp)
    {
      fprintf (stderr,
	       "error: you must either display interpreter or patch interpreter\n");
      return 1;
    }


  if (optind < argc)
    {
      target_elf = argv[optind];
    }
  else
    {
      fprintf (stderr, "error: No target ELF file specified\n");
      return 1;
    }

  if (!check_file_access (target_elf))
    {
      return 1;
    }

  if (interp && !check_file_access (interp))
    {
      return 1;
    }

  if (process_file (target_elf, interp) != 0)
    {
      fprintf (stderr, "error patching '%s'\n", target_elf);
      return 1;
    }

  return 0;

}
