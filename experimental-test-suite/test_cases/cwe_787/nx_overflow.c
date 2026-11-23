#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error "This test requires ARM64."
#endif

struct Context {
    unsigned char buffer[16];
    void (*callback)(void);
};

void normal_action(void) {
    puts("NORMAL_ACTION");
}

void vulnerable_overwrite(struct Context *ctx,
                          void (*target)(void)) {
    // Unafe behavior: overwrite adjacent callback.
    memcpy(ctx->buffer + offsetof(struct Context, callback),
           &target, sizeof(target));
}

int main(int argc, char *argv[]) {
    if (argc != 2 ||
        (strcmp(argv[1], "nx") != 0 &&
         strcmp(argv[1], "exec") != 0)) {
        fprintf(stderr, "Usage: %s nx|exec\n", argv[0]);
        return 1;
    }

    long page_size = sysconf(_SC_PAGESIZE);

    if (page_size <= 0) {
        fprintf(stderr, "Invalid page size\n");
        return 1;
    }

    void *memory = mmap(
        NULL, (size_t)page_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
    );

    if (memory == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Harmless ARM64 RET instruction
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

    struct Context ctx = {0};
    ctx.callback = normal_action;

    void (*target)(void) = (void (*)(void))memory;

    vulnerable_overwrite(&ctx, target);

    printf("Mode: %s\n", argv[1]);
    printf("Callback offset: %zu\n",
           offsetof(struct Context, callback));
    puts("CALLBACK_OVERWRITTEN");
    fflush(stdout);

    // Callback after CWE-787 memory corruption
    ctx.callback();

    puts("UNAUTHORIZED_EXECUTION");
    munmap(memory, (size_t)page_size);

    return 0;
}
