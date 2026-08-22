// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SHN_COMMON 0xFFF2
#define STT_OBJECT 1
#define STB_GLOBAL 1
#define STV_DEFAULT 0

struct elf64_hdr {
	unsigned char e_ident[16];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct elf64_shdr {
	uint32_t sh_name;
	uint32_t sh_type;
	uint64_t sh_flags;
	uint64_t sh_addr;
	uint64_t sh_offset;
	uint64_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint64_t sh_addralign;
	uint64_t sh_entsize;
};

struct elf64_sym {
	uint32_t st_name;
	unsigned char st_info;
	unsigned char st_other;
	uint16_t st_shndx;
	uint64_t st_value;
	uint64_t st_size;
};

static int is_ollvm_com(const char *name, const struct elf64_sym *s)
{
	if ((s->st_info & 0xF) != STT_OBJECT)
		return 0;
	if ((s->st_info >> 4) != STB_GLOBAL)
		return 0;
	if (s->st_other != STV_DEFAULT)
		return 0;
	if (s->st_shndx != SHN_COMMON)
		return 0;
	if (name[0] != 'x' && name[0] != 'y')
		return 0;
	if (name[1] != '\0' && name[1] != '.')
		return 0;
	return 1;
}

int main(int argc, char **argv)
{
	struct elf64_hdr *eh;
	struct elf64_shdr *sh;
	struct elf64_sym *syms;
	const char *strtab = "";
	unsigned char *mod;
	struct stat st;
	struct elf64_sym **ollvm;
	struct elf64_sym **fake;
	int nollvm = 0;
	int nfake = 0;
	int cap_o = 0;
	int cap_f = 0;
	int fd;
	int i;
	size_t size;

	if (argc < 3) {
		fprintf(stderr, "usage: %s <ko> <fake1> [fake2...]\n", argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	if (fstat(fd, &st)) {
		perror("fstat");
		return 1;
	}
	size = st.st_size;
	mod = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mod == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	eh = (struct elf64_hdr *)mod;
	if (memcmp(eh->e_ident, "\x7f""ELF", 4) || eh->e_ident[4] != 2) {
		fprintf(stderr, "not a 64bit elf\n");
		return 1;
	}

	ollvm = calloc(4096, sizeof(*ollvm));
	fake = calloc(4096, sizeof(*fake));
	cap_o = cap_f = 4096;

	sh = (struct elf64_shdr *)(mod + eh->e_shoff);
	for (i = 0; i < eh->e_shnum; i++) {
		const char *secname;
		uint32_t j;

		if (sh[i].sh_type != 2 || sh[i].sh_entsize != 24)
			continue;
		secname = (const char *)(mod +
			sh[eh->e_shstrndx].sh_offset + sh[i].sh_name);
		if (strcmp(secname, ".symtab"))
			continue;
		syms = (struct elf64_sym *)(mod + sh[i].sh_offset);
		strtab = (const char *)(mod + sh[sh[i].sh_link].sh_offset);
		for (j = 0; j < sh[i].sh_size / 24; j++) {
			const char *name = strtab + syms[j].st_name;

			if (is_ollvm_com(name, &syms[j])) {
				if (nollvm == cap_o)
					return 1;
				ollvm[nollvm++] = &syms[j];
			}
		}
	}

	for (i = 2; i < argc; i++) {
		uint32_t j;

		for (j = 0; j < eh->e_shnum; j++) {
			uint32_t k;

			if (sh[j].sh_type != 2 || sh[j].sh_entsize != 24)
				continue;
			if (strcmp((const char *)(mod +
				sh[eh->e_shstrndx].sh_offset + sh[j].sh_name),
				".symtab"))
				continue;
			syms = (struct elf64_sym *)(mod + sh[j].sh_offset);
			strtab = (const char *)(mod + sh[sh[j].sh_link].sh_offset);
			for (k = 0; k < sh[j].sh_size / 24; k++) {
				if (!strcmp(strtab + syms[k].st_name, argv[i])) {
					if (nfake == cap_f)
						return 1;
					fake[nfake++] = &syms[k];
					break;
				}
			}
		}
	}

	if (nfake < nollvm) {
		fprintf(stderr, "need %d fake symbols, have %d\n",
			nollvm, nfake);
		return 1;
	}

	for (i = 0; i < nollvm; i++) {
		struct elf64_sym *o = ollvm[i];
		struct elf64_sym *f = fake[nfake - 1 - i];
		uint32_t name;

		printf("swap %s <-> %s\n",
		       strtab + o->st_name, strtab + f->st_name);
		o->st_shndx = f->st_shndx;
		name = o->st_name;
		o->st_name = f->st_name;
		f->st_name = name;
	}

	msync(mod, size, MS_SYNC);
	munmap(mod, size);
	close(fd);
	printf("fixed %d common symbols\n", nollvm);
	return 0;
}
