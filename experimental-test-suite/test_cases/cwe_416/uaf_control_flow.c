#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

struct Session {
    void (*callback)(void);
    char padding[24];
};

void normal_action(void) {
    puts("NORMAL_ACTION");
}

void restricted_action(void) {
    puts("UNAUTHORIZED_ACTION");
}

void invoke_callback(struct Session *session) {
    // Unsafe when session is dangling
    session->callback();
}

int main(void) {
    // Create original session
    struct Session *old_session =
        malloc(sizeof(*old_session));

    if (old_session == NULL) {
        perror("malloc");
        return 1;
    }

    old_session->callback = normal_action;

    // Save the address before freeing  object
    uintptr_t old_address = (uintptr_t)old_session;

    free(old_session);

    // Make a replacement object of the same size
    struct Session *new_session =
        malloc(sizeof(*new_session));

    if (new_session == NULL) {
        perror("malloc");
        return 1;
    }

    // Check whether the allocator reused the address
    if ((uintptr_t)new_session != old_address) {
        puts("NO_REUSE");
        free(new_session);
        return 2;
    }

    new_session->callback = restricted_action;

    puts("ADDRESS_REUSED");
    fflush(stdout);

    // CWE-416: access through the dangling pointer
    invoke_callback(old_session);

    free(new_session);
    return 0;
}
