#include <stdio.h>
#include <string.h>

void stack_overflow_func(const char *input) {
	char buff [16];
	
	// unsafe operation
	strcpy(buff, input);
	
	printf("Input copied into buffer!\n");
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		return 1;
	}
	
	stack_overflow_func(argv[1]);

	printf("Program Finished!\n");

	return 0;
}


