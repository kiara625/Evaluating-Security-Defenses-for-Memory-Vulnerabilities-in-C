#include <stdio.h>
#include <string.h>
#include <stddef.h>

struct Context {
    unsigned char buffer[16];
    void (*callback)(void);
};

void normal_action(void) {
    puts("NORMAL_ACTION");
}

void restricted_action(void) {
    puts("UNAUTHORIZED_ACTION");
}

void vulnerable_function(int trigger_overflow) {
    struct Context ctx = {0};
    ctx.callback = normal_action;

    if (trigger_overflow) {
        unsigned char payload[sizeof(ctx)];

        memset(payload, 'A', sizeof(payload));

        void (*target)(void) = restricted_action;

        memcpy(
            payload + offsetof(struct Context, callback),
            &target,
            sizeof(target)
        );

        // Unsafe Behavior: copying more than
        // the 16-byte buffer can hold.
        memcpy(ctx.buffer, payload, sizeof(payload));
    }

    ctx.callback();
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s normal|overflow\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "normal") == 0) {
        vulnerable_function(0);
    } else if (strcmp(argv[1], "overflow") == 0) {
        vulnerable_function(1);
    } else {
        return 1;
    }

    return 0;
}
