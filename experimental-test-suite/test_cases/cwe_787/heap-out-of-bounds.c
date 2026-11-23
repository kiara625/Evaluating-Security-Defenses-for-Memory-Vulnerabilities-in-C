
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

struct Record {
    unsigned char data[16];
    unsigned int authorized;
};

void func(struct Record *record,
                      size_t index,
                      unsigned char value) {
    // Unsafe behavior
    record->data[index] = value;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        return 1;
    }

    char *end;
    unsigned long index = strtoul(argv[1], &end, 10);

    if (*end != '\0') {
        fprintf(stderr, "Invalid index\n");
        return 1;
    }

    struct Record *record = calloc(1, sizeof(*record));
    if (record == NULL) {
        perror("calloc");
        return 1;
    }

    printf("Authorization field offset: %zu\n",
           offsetof(struct Record, authorized));

    func(record, (size_t)index, 1);

    if (record->authorized != 0) {
        puts("ACCESS_GRANTED");
    } else {
        puts("ACCESS_DENIED");
    }

    printf("Authorization value: %u\n",
           record->authorized);

    free(record);
    return 0;
}
