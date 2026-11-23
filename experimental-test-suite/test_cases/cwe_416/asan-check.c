#include <stdio.h>
#include <stdlib.h>

struct Session {
    unsigned int authorized;
    char padding[28];
};

unsigned int check_authorization(
    const struct Session *session
) {
    return session->authorized;
}

int main(void) {
    struct Session *session = malloc(sizeof(*session));

    if (session == NULL) {
        perror("malloc");
        return 1;
    }

    session->authorized = 0;

    free(session);

    // Unsafe behavior
    unsigned int result = check_authorization(session);

    printf("Authorization value: %u\n", result);
    return 0;
}
