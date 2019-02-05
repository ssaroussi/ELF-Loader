#ifndef ELF_LOADER_ELF_H
#define ELF_LOADER_ELF_H

#include <stdint.h>
#include <stdbool.h>
#include <elf.h>
#include <unistd.h>

#ifdef __i386__
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Rel Elf_Rel;
typedef Elf32_Word Elf_Word;
#define ELF_R_SYM(x) ELF32_R_SYM(x)
#define ELF_R_TYPE(x) ELF32_R_TYPE(x)
#endif

#ifdef __x86_64__
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Sym Elf_Sym;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Rel Elf_Rel;
typedef Elf64_Word Elf_Word;
#define ELF_R_SYM(x) ELF64_R_SYM(x)
#define ELF_R_TYPE(x) ELF64_R_TYPE(x)
#endif

#define PROT_READ    0x1        /* page can be read */
#define PROT_WRITE    0x2        /* page can be written */
#define PROT_EXEC    0x4        /* page can be executed */
#define PROT_SEM    0x8        /* page may be used for atomic ops */
#define PROT_NONE    0x0        /* page can not be accessed */
#define PROT_GROWSDOWN    0x01000000    /* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP    0x02000000    /* mprotect flag: extend change to end of growsup vma */

#define cacheflush(a1, a2, a3) __builtin___clear_cache(a1, a1 + a2)

#define MAP_SHARED    0x01        /* Share changes */
#define MAP_PRIVATE    0x02        /* Changes are private */
#define MAP_TYPE    0x0f        /* Mask for type of mapping */
#define MAP_FIXED    0x10        /* Interpret addr exactly */
#define MAP_ANONYMOUS    0x20        /* don't use a file */
#ifdef CONFIG_MMAP_ALLOW_UNINITIALIZED
# define MAP_UNINITIALIZED 0x4000000	/* For anonymous mmap, memory could be uninitialized */
#else
# define MAP_UNINITIALIZED 0x0        /* Don't support this flag */
#endif


#define ELFMAG_LEN    (4)

#define PAGE_SIZE (sysconf(_SC_PAGESIZE))
#define STACK_SIZE (8*1024*1024)
#define STACK_STORAGE_SIZE 0x5000
#define STACK_STRING_SIZE 0x5000

bool elf_validate_magic(Elf64_Ehdr *hdr);

bool elf_check_supported(Elf64_Ehdr *hdr);

bool elf_load_program_segments(void *elf_start, uint64_t *entry_p, uint64_t *base_addr, uint64_t *stack_p);

static inline void error(const char *msg);

static inline void debug(const char *msg);

static inline intptr_t round_up(size_t x, size_t y);

static inline intptr_t round_down(size_t x, size_t y);

static inline int generate_protection(int flags);

#endif //ELF_LOADER_ELF_H
