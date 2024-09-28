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

#include "hopper_elf.h"

/* Options for patching/displaying information */
bool verbose = false;
bool show_symbols = false;
bool disp_interp = false;
bool dump_shellcode = false;

int process_file(const char *file_name, const char *new_interp)
{
    Elf64_Off table_offset = 0;
    Elf64_InterpInfo interpinfo;
    Elf64_FileInfo elfobj;

    /* Init our interpreter info structure to default values */
    interpinfo.offset = 0;
    interpinfo.size = 0;
    interpinfo.index = 0;
    interpinfo.old_name = NULL;

    if (new_interp) {
	interpinfo.new_name = strdup(new_interp);
    } else {
	interpinfo.new_name = NULL;
    }

    elfobj.file_name = strdup(file_name);
    if (load_elf64_file(&elfobj) != ELF_LOAD_SUCCESS) {
	fprintf(stderr, "error: unable to load %s\n", elfobj.file_name);
	return -1;
    }

    if (verify_elf64_binary(&elfobj.ehdr) != ELF_VALID) {
	fprintf(stderr, "error: %s is not a 64BIT DYN binary\n",
		elfobj.file_name);
	free(elfobj.phdr);
	free(elfobj.shdr);
	fclose(elfobj.handle);
	return -1;
    }

    if (dump_shellcode) {
        parse_elf64_obj_print_shellcode(&elfobj);
    }

    /* Find our PT_INTERP segment, this must exist to continue */
    if (disp_interp || interpinfo.new_name) {
	int seg_idx = find_elf64_segment_index(&elfobj, PT_INTERP);
	if (seg_idx != SEG_NOT_FOUND) {
	    if (verbose) {
		printf("Found PT_INTERP segment at 0x%016lx\n",
		       elfobj.phdr[seg_idx].p_vaddr);
		printf("Offset: 0x%lx\n", elfobj.phdr[seg_idx].p_offset);
		printf("Size: %zu\n", elfobj.phdr[seg_idx].p_filesz);
		print_flags(elfobj.phdr[seg_idx].p_flags);
	    }
	    interpinfo.offset = elfobj.phdr[seg_idx].p_offset;
	    interpinfo.size = (Elf64_Xword) elfobj.phdr[seg_idx].p_filesz;
	    interpinfo.index = seg_idx;
	} else {
	    fprintf(stderr, "error: no PT_INTERP segment found\n");
	    free(elfobj.phdr);
	    fclose(elfobj.handle);
	    return -1;
	}
    }

    /* If -s has been passed we need to get information to display
     * symbol information
     */
    if (show_symbols) {
	char *sym_table = get_elf64_symbol_table(&elfobj);
	if (sym_table == NULL) {
	    free(elfobj.phdr);
	    fclose(elfobj.handle);
	    return -1;
	}

	for (int i = 0; i < elfobj.ehdr.e_shnum; i++) {
	    if (elfobj.shdr[i].sh_type == SHT_SYMTAB
		|| elfobj.shdr[i].sh_type == SHT_DYNSYM) {
		const char *symtab_name =
		    sym_table + elfobj.shdr[i].sh_name;
		printf("Symbol Table '%s' (STT_FUNC):\n", symtab_name);
		print_elf64_symbols(elfobj.handle, &elfobj.shdr[i],
				    elfobj.shdr[elfobj.shdr[i].
						sh_link].sh_offset,
				    STT_FUNC);
	    }
	}

	free(elfobj.shdr);
	free(sym_table);
    }

    /* At this point interpinfo.offset holds the offset of the path of the
     * interpreter
     */
    fseek(elfobj.handle, interpinfo.offset, SEEK_SET);
    char *interp = malloc(interpinfo.size);
    if (interp == NULL) {
	free(elfobj.phdr);
	free(elfobj.shdr);
	fclose(elfobj.handle);
	return -1;
    }

    size_t b_read = fread(interp, 1, interpinfo.size, elfobj.handle);
    if (b_read != interpinfo.size) {
	free(interp);
	free(elfobj.phdr);
	return -1;
    }

    /* Display and/or patch the interpreter */
    interpinfo.old_name = interp;
    if (disp_interp) {
	printf("0x%lx:PT_INTERP = %s\n", interpinfo.offset,
	       interpinfo.old_name);
    }

    if (interpinfo.new_name) {
	patch_interpreter(&elfobj, interpinfo);
    }

    free(interp);
    free(elfobj.phdr);
    fclose(elfobj.handle);

    return 0;

}

void print_usage(const char *program_name)
{
    fprintf(stderr,
	    "Hopper the ELF64 tool by Travis Montoya <trav@hexproof.sh>\n");
    fprintf(stderr, "usage: %s [option(s)] [target]\n", program_name);
    fprintf(stderr, "  -v                 show verbose output\n");
    fprintf(stderr,
	    "  -s                 display symbol information (STT_FUNC)\n");
    fprintf(stderr,
	    "  -c                 dump '.text' section as shellcode\n");
    fprintf(stderr, "  -d                 display interpreter\n");
    fprintf(stderr, "  -p [interpreter]   patch interpreter\n");
    fprintf(stderr,
	    "\nYou can run '%s -search' to list common interpreters on your system\n",
	    program_name);
}

int main(int argc, char *argv[])
{
    int opt;
    char *interp = NULL;
    char *target_elf = NULL;

    if (argc < 2) {
	print_usage(argv[0]);
	return 1;
    }

    /* If we are just searching do nothing further */
    if (argc == 2 && strncmp(argv[1], "-search", 7) == 0) {
	print_interps();
	return 0;
    }

    while ((opt = getopt(argc, argv, "vsdcp:")) != -1) {
	switch (opt) {
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
	case 'c':
	    dump_shellcode = true;
	    break;
	default:
	    print_usage(argv[0]);
	    return 1;
	}
    }

    if (disp_interp && interp) {
	fprintf(stderr,
		"error: You cant patch and display the interpreter\n");
	return 1;
    }

    /*
       if (!disp_interp && !interp) {
       fprintf(stderr,
       "error: you must either display interpreter or patch interpreter\n");
       return 1;
       } */


    if (optind < argc) {
	target_elf = argv[optind];
    } else {
	fprintf(stderr, "error: No target ELF file specified\n");
	return 1;
    }

    if (!check_file_access(target_elf)) {
	return 1;
    }

    if (interp && !check_file_access(interp)) {
	return 1;
    }

    if (process_file(target_elf, interp) != 0) {
	fprintf(stderr, "error patching '%s'\n", target_elf);
	return 1;
    }

    return 0;

}
