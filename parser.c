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

/* 
 * Finds the text section of an object file and prints it out
 * as shellcode
 */
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

/*
 * Parses the headers and section/program headers of an ELF64 binary
 */
int parse_elf64(Elf64_FileInfo * fi) {
    const int WIDTH = 10;

    if (fi == NULL) {
	    return -1;
    }

    printf("ELF Header:\n");
    printf("  Entry point: 0x%016lx\n", fi->ehdr.e_entry);

    printf("  Type: ");
    switch (fi->ehdr.e_type) {
	    case ET_NONE:
		    printf("No file type\n");
		    break;
	    case ET_REL:
		    printf("Relocatable file\n");
		    break;
	    case ET_EXEC:
		    printf("Executable file\n");
		    break;
	    case ET_DYN:
		    printf("Shared object file\n");
		    break;
	    case ET_CORE:
		    printf("Core file\n");
		    break;
	    default:
		    printf("Unknown\n");
		    break;
    }

    printf("  Class: ");
	switch(fi->ehdr.e_ident[EI_CLASS]) {
	    case ELFCLASSNONE:
		    printf("None\n");
		    break;
	    case ELFCLASS32:
		    printf("32-Bit\n");
		    break;
	    case ELFCLASS64:
		    printf("64-Bit\n");
		    break;
	    case ELFCLASSNUM:
		    printf("%d\n", fi->ehdr.e_ident[EI_CLASS]);
		    break;
	    default:
		    printf("Unknown\n");
		    break;
	}

    printf("  Data: ");
    switch(fi->ehdr.e_ident[EI_DATA]) {
	case ELFDATANONE:
		printf("Inalid data encoding\n");
		break;
	case ELFDATA2LSB:
		printf("2's complement, little endian\n");
		break;
	case ELFDATA2MSB:
		printf("2's complement, big endian\n");
		break;
	case ELFDATANUM:
		printf("%d\n", fi->ehdr.e_ident[EI_DATA]);
		break;
	default:
		printf("Unknown\n");
		break;
    }


    printf("  ABI: ");
    switch(fi->ehdr.e_ident[EI_OSABI]) {
	case ELFOSABI_NONE:
		printf("UNIX System V ABI\n");
		break;
	case ELFOSABI_NETBSD:
		printf("NetBSD\n");
		break;
	case ELFOSABI_LINUX:
		printf("GNU\\Linux\n");
		break;
	case ELFOSABI_FREEBSD:
		printf("FreeBSD\n");
		break;
	case ELFOSABI_OPENBSD:
		printf("OpenBSD\n");
		break;
	default:
		printf("Unknown\n");
		break;
    }

    printf("  ABI Version: %d\n", fi->ehdr.e_ident[EI_ABIVERSION]);
    printf("  File Version: %d\n", fi->ehdr.e_ident[EI_VERSION]);

    printf("  Program header offset: 0x%016lx\n", fi->ehdr.e_phoff);
    printf("  Section header offset: 0x%016lx\n", fi->ehdr.e_shoff);
    printf("  ELF header size: %d (bytes)\n", fi->ehdr.e_ehsize);
    printf("  Program header size: %d (bytes)\n", fi->ehdr.e_phentsize);
    printf("  Program header count: %d\n", fi->ehdr.e_phnum);
    printf("  Section header size: %d (bytes)\n", fi->ehdr.e_shentsize);
    printf("  Section header count: %d\n", fi->ehdr.e_shnum);
    printf("  Section header string table index: %d\n", fi->ehdr.e_shstrndx);

    printf("Program headers:\n");
    for (int i = 0; i < fi->ehdr.e_phnum; i++) {
	switch(fi->phdr[i].p_type) {
		case PT_LOAD:
			if (fi->phdr[i].p_offset == 0) {
				printf("  .text     0x%016lx\n", fi->phdr[i].p_vaddr);
			} else {
				printf("  .data     0x%016lx\n", fi->phdr[i].p_vaddr);
			}
			break;
		case PT_PHDR:
			printf("  Program segment: 0x%016lx\n", fi->phdr[i].p_vaddr);
			break;
		case PT_DYNAMIC:
			printf("  Dynamic segment: 0x%016lx\n", fi->phdr[i].p_vaddr);
			break;
		case PT_NOTE:
			printf("  Note segment: 0x%016lx\n", fi->phdr[i].p_vaddr);
			break;
		case PT_INTERP:
			char * interp = malloc(fi->phdr[i].p_filesz);
			fseek(fi->handle, fi->phdr[i].p_offset, SEEK_SET);
			fread(interp, 1, fi->phdr[i].p_filesz, fi->handle);
			printf("  Interpreter: %s\n", interp);
			free (interp);
			break;

	}
    }

    char *sym_table = get_elf64_symbol_table(fi);
    printf("Section headers:\n");
    for (int i = 1; i < fi->ehdr.e_shnum; i++) {
	printf("  %s    0x%016lx\n", (sym_table + fi->shdr[i].sh_name), fi->shdr[i].sh_addr);
    }

    return 0;
}
