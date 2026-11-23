#include <stdio.h>
#include <string.h>

struct UserData {
	char input[16];
	unsigned int authorized;
};

void func(const char *user_input) {
	struct UserData data = {
		.input = {0},
		.authorized = 0
	};

	strcpy(data.input, user_input);

	if (data.authorized != 0 ) {
		puts("ACCESS_GRANTED");
	} else {
		puts("ACCESS_DENIED");
	}

	printf("Authoriztion value: %u\n", data.authorized);
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		return 1;
	}

	func(argv[1]);
	return 0;
}
