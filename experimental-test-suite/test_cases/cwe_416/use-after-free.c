#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

struct Session {
    unsigned int authorized;
    char padding[28];
};

unsigned int check_authorization(const struct Session *session) {
    return session->authorized;
}

int main(void) {
    struct Session *old_session = malloc(sizeof(*old_session));

    if (old_session == NULL) {
        perror("malloc");
        return 1;
    }

    old_session->authorized = 0;

    // Save the original address for comparison
    uintptr_t old_address = (uintptr_t)old_session;

    free(old_session);

    // old_session = dangling pointer
    struct Session *new_session = malloc(sizeof(*new_session));

    if (new_session == NULL) {
        perror("malloc");
        return 1;
    }

    if ((uintptr_t)new_session != old_address) {
        puts("NO_REUSE");
        free(new_session);
        return 2;
    }

    new_session->authorized = 1;

    // Unsafe behavior
    unsigned int result = check_authorization(old_session);

    if (result != 0) {
        puts("ACCESS_GRANTED");
    } else {
        puts("ACCESS_DENIED");
    }

    printf("Authorization value: %u\n", result);

    free(new_session);
    return 0;
}
