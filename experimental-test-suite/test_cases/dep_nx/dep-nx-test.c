#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2 ||
        (strcmp(argv[1], "nx") != 0 &&
         strcmp(argv[1], "exec") != 0)) {
        fprintf(stderr, "Usage: %s nx|exec\n", argv[0]);
        return 1;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        perror("sysconf");
        return 1;
    }

    void *memory = mmap(
        NULL,
        (size_t)page_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    if (memory == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // ARM64 instruction: RET
    // Returns immediately without performing any operation
    const unsigned char instruction[] = {
        0xC0, 0x03, 0x5F, 0xD6
    };

    memcpy(memory, instruction, sizeof(instruction));

    __builtin___clear_cache(
        (char *)memory,
        (char *)memory + sizeof(instruction)
    );

    int permissions = PROT_READ;

    if (strcmp(argv[1], "exec") == 0) {
        permissions |= PROT_EXEC;
    }

    if (mprotect(memory, (size_t)page_size, permissions) != 0) {
        perror("mprotect");
        munmap(memory, (size_t)page_size);
        return 1;
    }

    printf("Mode: %s\n", argv[1]);
    printf("Executable permission: %s\n",
           (permissions & PROT_EXEC) ? "YES" : "NO");
    fflush(stdout);

    // Attempt to execute the instruction in the mapped page
    void (*function)(void) = (void (*)(void))memory;
    function();

    puts("EXECUTION_SUCCEEDED");

    munmap(memory, (size_t)page_size);
    return 0;
}
