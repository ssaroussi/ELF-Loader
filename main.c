#include <stdio.h>
#include <stdlib.h>
#include "elf.h"


int main(int argc, char *argv[], char *envp[]) {
    FILE *f = fopen(argv[1], "rb");
    uint64_t entry = 0;
    uint64_t base = 0;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0L, SEEK_SET);

    char *file = (char *) malloc((size_t) (size + 1));

    if (!file) {
        puts("Can not locate memory");
        abort();
    }

    fread(file, (size_t) size, 1, f);
    fclose(f);

    elf_load_program_segments(file, &entry, &base, NULL);

    free(file);

    return 0;
}
