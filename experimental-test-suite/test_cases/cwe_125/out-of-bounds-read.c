#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

struct Record {
    unsigned char data[16];
    char secret[7];
};

unsigned char func(const struct Record *record,
                              size_t index) {
    // Unsafe behavior
    return record->data[index];
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

    memset(record->data, 'B', sizeof(record->data));
    memcpy(record->secret, "SECRET", 7);

    printf("Secret field offset: %zu\n",
           offsetof(struct Record, secret));

    unsigned char value =
        func(record, (size_t)index);

    printf("READ_VALUE: 0x%02X\n", value);

    free(record);
    return 0;
}
