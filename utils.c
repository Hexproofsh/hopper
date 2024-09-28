/* utils.c - helper functions for hopper
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
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "hopper_elf.h"

int load_elf64_file(Elf64_FileInfo * fi) {
    if (fi == NULL) {
	    return -1;
    }

    if ((fi->handle = fopen(fi->file_name, "r+b")) == NULL) {
	    return -1;
    }

    fread(&fi->ehdr, sizeof(fi->ehdr), 1, fi->handle);
    fi->phdr = malloc(fi->ehdr.e_phnum * sizeof(Elf64_Phdr));
    if (fi->phdr == NULL) {
	    return -1;
    }

    fseek(fi->handle, fi->ehdr.e_phoff, SEEK_SET);
    fread(fi->phdr, sizeof(Elf64_Phdr), fi->ehdr.e_phnum, fi->handle);

    fi->shdr = malloc(fi->ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (fi->shdr == NULL) {
	    return -1;
    }

    return 0;
}

/* Verifies the target binary is ELF64 dynamically linked */
int verify_target_binary(Elf64_Ehdr * ehdr)
{
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
	ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
	return -1;
    }

    if (ehdr->e_type != ET_DYN) {
	return -1;
    }

    printf("ELF file is a 64-Bit Shared Object (DYN) file\n\n");
    return 0;

}

/* Check if file exists */
int check_file_access(const char *file_path)
{
    if (access(file_path, F_OK) != 0) {
	fprintf(stderr, "error: unable to access '%s': %s\n", file_path,
		strerror(errno));
	return 0;
    }
    return 1;
}

/* Pretty print p_flags */
void print_flags(Elf64_Word p_flags)
{
    printf("Flags (p_flags): 0x%x ( ", p_flags);
    if (p_flags & PF_R)
	printf("R");
    if (p_flags & PF_W)
	printf("W");
    if (p_flags & PF_X)
	printf("E");
    printf(" )\n");

    printf("  Read:    %s\n", (p_flags & PF_R) ? "Yes" : "No");
    printf("  Write:   %s\n", (p_flags & PF_W) ? "Yes" : "No");
    printf("  Execute: %s\n", (p_flags & PF_X) ? "Yes" : "No");
}

/* List the interpreters on local system */
void print_interps()
{
    const char *dirs[] = { "/lib", "/lib64", "/usr/lib", "/usr/lib64" };
    DIR *dir;
    struct dirent *entry;
    char full_path[1024];
    struct stat file_stat;
    int count = 0;

    printf("Searching for interpreters on local system...\n\n");
    for (int i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
	dir = opendir(dirs[i]);
	if (!dir) {
	    continue;
	}

	while ((entry = readdir(dir)) != NULL) {
	    if (strcmp(entry->d_name, ".") == 0
		|| strcmp(entry->d_name, "..") == 0) {
		continue;
	    }

	    snprintf(full_path, sizeof(full_path), "%s/%s", dirs[i],
		     entry->d_name);

	    if (stat(full_path, &file_stat) == 0
		&& S_ISREG(file_stat.st_mode)) {
		if (strstr(entry->d_name, "ld-linux") != NULL) {
		    printf("%s\n", full_path);
		    count++;
		}
	    }
	}
	closedir(dir);
    }
    printf("\nFound (%d) interpreters\n", count);
}
