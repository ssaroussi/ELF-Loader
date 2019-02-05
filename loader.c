#include <string.h>
#include <stdlib.h>

#include "loader.h"

inline void error(const char *msg) {
	perror(msg);
	abort();
}

unsigned char elf_validate_magic(Elf32_Ehdr* hdr) {
	if (!hdr) return (0);
	return !memcmp(hdr->e_ident, ELFMAG, ELFMAG_LEN);
}

unsigned char elf_check_supported(Elf32_Ehdr *hdr) {
	if (!elf_validate_magic(hdr)) {
		error ("Invalid ELF File\n");
	} else
}


int main (int argc, char *argv[], char *envp[]) {


	return (0);
}
