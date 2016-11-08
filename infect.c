/*
 * infect-to-protect: Produces an ELF executable with a whitelist of syscalls
 * Copyright (c) 2016 Leandro Pereira <leandro@tia.mat.br>
 *
 * Based on infect: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 *
 * License GPLv2+: GNU GPL version 2 or later.
 *
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <elf.h>

/* This array contains the relocatable assembly program.  In it is a 32-bit
 *  jump, which needs to be modified to point to an actual target.  */
static unsigned char infection[] = {
#include "shellcodegen.h"
};

/* Display an error message and exit the program. */
static void bail(char const *prefix, char const *msg)
{
    fprintf(stderr, "%s: %s\n", prefix, msg);
    exit(EXIT_FAILURE);
}

/* Map a file into read-write memory. The return value is a pointer to
 * the beginning of the file image. If utimbuf is not NULL, it receives
 * the file's current access and modification times. */
static void *mapfile(char const *filename)
{
    struct stat stat;
    void *ptr;
    int fd;

    fd = open(filename, O_RDWR);
    if (fd < 0)
	bail(filename, strerror(errno));
    if (fstat(fd, &stat))
	bail(filename, strerror(errno));
    if (!S_ISREG(stat.st_mode))
	bail(filename, "not an ordinary file.");
    ptr = mmap(NULL, stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED)
	bail(filename, strerror(errno));
    return ptr;
}

/* Examine the program segment header table and look for a segment
 * that is loaded into executable memory and is followed by enough padding
 * for our infection program to fit into. The return value is negative if
 * an appropriate segment cannot be found.
 */
static int findinfectionphdr(Elf64_Phdr const *phdr, int count)
{
    Elf64_Off pos, endpos;
    int i, j;

    for (i = 0 ; i < count ; ++i) {
	if (phdr[i].p_filesz > 0 && phdr[i].p_filesz == phdr[i].p_memsz
				 && (phdr[i].p_flags & PF_X)) {
	    pos = phdr[i].p_offset + phdr[i].p_filesz;
	    endpos = pos + sizeof infection;
	    for (j = 0 ; j < count ; ++j) {
		if (phdr[j].p_offset >= pos && phdr[j].p_offset < endpos
					    && phdr[j].p_filesz > 0)
		    break;
	    }
	    if (j == count)
		return i;
	}
    }
    return -1;
}

/* main().
 */
int main(int argc, char *argv[])
{
    char const *filename;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Off pos;
    char *image;
    int n;

    if (argc != 2)
	bail("Usage", "infect FILENAME");
    filename = argv[1];

    /* Load the file into memory and verify that it is a 64-bit ELF
     * executable.
     */
    image = mapfile(filename);
    if (memcmp(image, ELFMAG, SELFMAG))
	bail(filename, "not an ELF file.");
    if (image[EI_CLASS] != ELFCLASS64)
	bail(filename, "not a 64-bit ELF file.");
    ehdr = (Elf64_Ehdr*)image;
    if (ehdr->e_type != ET_EXEC)
	bail(filename, "not an executable file.");

    /* Find a suitable location for our infection.
     */
    phdr = (Elf64_Phdr*)(image + ehdr->e_phoff);
    n = findinfectionphdr(phdr, ehdr->e_phnum);
    if (n < 0)
	bail(filename, "unable to find a usable infection point");

    /* Modify the executable's entry address to point to the chosen
     * location, and modify the infection program to jump to the
     * original entry address after it has finished.
     */
    pos = phdr[n].p_vaddr + phdr[n].p_filesz;
    char *ptr = memmem(infection, sizeof(infection),
	"\xe9\x00\x00\x00\x00", 5);
    if (!ptr)
        bail(filename, "Could not find dummy jump point");

    /* I don't know why 244 is needed. */
    Elf64_Word new_entry = (Elf64_Word)ehdr->e_entry - (pos + sizeof infection) + 244;
    memcpy(ptr + 1, &new_entry, sizeof(new_entry));
    ehdr->e_entry = pos;

    /* Insert the infection program into the executable. */
    memcpy(image + phdr[n].p_offset + phdr[n].p_filesz,
	   infection, sizeof infection);
    phdr[n].p_filesz += sizeof infection;
    phdr[n].p_memsz += sizeof infection;

    return 0;
}
