#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "elf.h"


/**
 * @brief Check if the file has an ELF magic
 * 
 * @param hdr A pointer to the elf header
 * @return true If the file is an ELF file
 * @return false If the file is not an ELF file
 */
bool elf_validate_magic(Elf_Ehdr *hdr) {
    if (!hdr) return (0);
    return !memcmp(hdr->e_ident, ELFMAG, ELFMAG_LEN);
}

/**
 * @brief Check if the file spesific foramt is compatable with this loader.
 * 
 * @param hdr A pointer to the elf header
 * @return true If the file is supported
 * @return false If the file is not supported
 */
bool elf_check_supported(Elf_Ehdr *hdr) {
    if (!elf_validate_magic(hdr))
        error("Invalid ELF File\n");

    if (hdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        hdr->e_ident[EI_CLASS] != ELFCLASS32 ||
        hdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        hdr->e_ident[EI_VERSION] != EV_CURRENT) {
        error("Unsupported ELF file\n");
    }

    return true;
}

/**
 * @brief Rounds up by x and y (aligning)
 * 
 * @param x The value to round
 * @param y The 'scale'
 * @return intptr_t The rounded value
 */
inline intptr_t round_up(size_t x, size_t y) {
    return (x + y - 1) & -y;
}

/**
 * @brief Rounds down by x and y (aligning)
 * 
 * @param x The value to round
 * @param y The 'scale'
 * @return intptr_t The rounded value
 */
inline intptr_t round_down(size_t x, size_t y) {
    return (x & -y);
}

/**
 * @brief Generates a protection flag.
 * 
 * @param flags The desired protection flags of the memory chunk.
 * @return int A valid flag (for mprotect)
 */
inline int generate_protection(int flags) {
    return (((flags & PF_R) && PROT_READ) ||  /* Read */
            ((flags & PF_W) && PROT_WRITE) ||  /* Write */
            ((flags & PF_X) && PROT_EXEC));     /* Execute */
}

/**
 * @brief Parsing and Loading Program Headers (sections)
 * 
 * @param elf_start A pointer to the beginning of the ELF file.
 * @param entry_p A pointer to the elf's entry point
 * @param base_addr A pointer to the base address
 * @param stack_p A pointer to the stack
 * @return true If the ELF was loaded successfully
 * @return false If there was a problem along the way
 */
bool elf_load_program_segments(void *elf_start, uint64_t *entry_p,
                               uint64_t *base_addr, uint64_t *stack_p) {
    Elf_Ehdr *hdr = (Elf_Ehdr *) elf_start; /* ELF header */
    Elf_Phdr *phdr = NULL;  /* Array of program headers */
    int s_permissions = 0;  /* segment permissions (r/w/x) */
    intptr_t base = 0;

    if (!hdr || !elf_check_supported(hdr)) return false;

    if (entry_p)
        *entry_p = hdr->e_entry;

    /* Check whether the file is PIE (dynamic) */
    if (hdr->e_type == ET_DYN) {
        base = (size_t) mmap(0, 100 * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        munmap((void *) base, 100 * PAGE_SIZE);
    }

    phdr = (Elf_Phdr *) (hdr->e_phoff + elf_start);
    /* Iterate through the program headers (which describes the segments), and allocating them. */
    for (size_t i = 0; i < hdr->e_phnum; i++) {
        switch (phdr[i].p_type) {
            /* Regular segment */
            case PT_LOAD:
                /* Ignore NULL Segments */
                if (phdr[i].p_filesz == 0) continue;

                /* Define the beginning of the map, and it's size */
                void *map_start = (void *) round_down(phdr[i].p_vaddr, PAGE_SIZE);
                size_t round_down_size = (void *) phdr[i].p_vaddr - map_start;
                size_t map_size = round_up(phdr[i].p_memsz + round_down_size, PAGE_SIZE);

                /* Allocate memory */
                mmap(base + map_start, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);

                /* Copy the segment's data */
                memcpy((void *) base + phdr[i].p_vaddr, elf_start + phdr[i].p_offset, phdr[i].p_filesz);

                /* Initiate the bss, if exists */
                if (phdr[i].p_memsz > phdr[i].p_filesz)
                    memset((void *) (base + phdr[i].p_vaddr + phdr[i].p_filesz), 0, phdr[i].p_memsz - phdr[i].p_filesz);

                /* Protect the segment */
                mprotect((unsigned char *) (base + map_start), map_size, generate_protection(phdr[i].p_flags));

                /* Clear the cache */
                cacheflush(base + map_start, (size_t) (map_start + map_size), 0);

                /* Relocate the base adress */
                if (base_addr != NULL && (*base_addr == -1 || *base_addr > (size_t) (map_start)))
                    *base_addr = (size_t) (map_start + base);

                break;

                /* Stack segment */
            case PT_GNU_STACK:
                if (!stack_p) continue;
                /* Here we only protect the stack. It's initialization happens in exec. */
                mprotect(stack_p, STACK_SIZE, generate_protection(phdr[i].p_flags));
                break;
        }
    }

    return true;
}

/**
 * @brief Executes an ELF file
 * 
 * @param file The content of the ELF file.
 * @param argv The arguments of the program
 * @param env The environment variables
 */
void elf_execute(void *file, char *argv[], char *env[]) {
    uint64_t e_entry = 0,
            base_addr = 0;

    /* Check whether the file is executable */
    Elf_Ehdr *hdr = (Elf_Ehdr *) elf_start; /* ELF header */
    if (!hdr) error("Can not load the elf.");
    
    if (hdr->e_type != ET_DYN || hdr->e_type == ET_EXEC) {
        error("The file is not executable");
        return;
    }
    /* Initiate the stack */
    /* TODO:
        [x] Allocate space
        [x] Load the program headers
        [] Copy argc, argv and env into the stack
    */
    intptr_t *stack = mmap(0, STACK_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    
    /* Load the segments */
    elf_load_program_segments(file, &e_entry, &base_addr, stack);
    memset(stack, 0, STACK_STORAGE_SIZE);

    uintptr_t *stack_storage = stack + STACK_SIZE - (STACK_STORAGE_SIZE + STACK_STRING_SIZE);
    char *string_storage = stack + STACK_SIZE - STACK_STRING_SIZE;

    /* Set argc, argv and envp */
    uintptr_t *s_argc = stack_storage,
            *s_argv = &stack_storage[1];

    *s_argc = argc;
    intptr_t *stack_p = 1;

     // TODO: copy_to_stack(stack_p, )

    /* Initiate a dynamic loader (interpreter) */

    /* Execute ctors from .init and from .init_arr */

    /* Prepare the stack with PHDR, PHNUM, PGSIZE, BASE, FLAGS, ENTRY, UID, EUID, GID, EGID, RANDOMSHIT, NULL */

    /* Jump to the pointer (the stack) */
}

void copy_to_stack(intptr_t *stack, intptr_t **arr, intptr_t **s_arr, size_t size, char *str_p, uintptr_t *stack_storage, uintptr_t *stack_p) {
    size_t curr_str_len = 0;

    for (int i = 0; i < size; i++) {
        curr_str_len = strlen(arr[i]);
        memcpy(stack_storage + *str_p, arr[i], curr_str_len);
        s_arr[i] = (uint64_t) &string_storage[*str_p];
        *str_p += curr_str_len;
        *stack_p++;
    }

    /* Since it is null-terminated. */
    stack_storage[*stack_p++] = '\0';
}

/**
 * 
 * @brief Reports to stderr and crashing the program.
 * 
 * @param msg The report's content.
 */
inline void error(const char *msg) {
    perror(msg);
    abort();
}

/**
 * @brief Reports to stdout only if debug is set.
 * 
 * @param msg The report's content
 */
inline void debug(const char *msg) {
#ifndef NDEBUG
    printf("DEBUG: %s", msg);
#endif
}
