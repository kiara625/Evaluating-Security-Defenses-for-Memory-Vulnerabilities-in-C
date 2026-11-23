#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>

struct Context {
    unsigned char buffer[16];
    void (*callback)(void);
};

void normal_action(void) {
    puts("NORMAL_ACTION");
}

void unauth_action(void) {
    puts("UNAUTHORIZED_ACTION");
}

void update(struct Context *ctx, uintptr_t guess) {
    // Unsafe behavior
    memcpy(ctx->buffer + offsetof(struct Context, callback),
           &guess, sizeof(guess));
}

int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "--probe") == 0) {
        printf("TARGET_ADDR=0x%" PRIxPTR "\n",
               (uintptr_t)&unauth_action);
        printf("CALLBACK_OFFSET=%zu\n",
               offsetof(struct Context, callback));
        return 0;
    }

    if (argc != 3 || strcmp(argv[1], "--attack") != 0) {
        fprintf(stderr,
                "Usage: %s --probe | --attack <address>\n",
                argv[0]);
        return 1;
    }

    char *end;
    unsigned long long supplied = strtoull(argv[2], &end, 0);

    if (*end != '\0') {
        fprintf(stderr, "Invalid address\n");
        return 1;
    }

    struct Context ctx = {0};
    ctx.callback = normal_action;

    update(&ctx, (uintptr_t)supplied);

    // Potentially overwritten function pointer
    ctx.callback();

    return 0;
}
