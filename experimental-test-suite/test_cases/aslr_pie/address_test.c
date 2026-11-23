#include <stdio.h>

void func(void) {
	puts("Test function executed");
}

int main(void) {
	printf("Function address: %p\n", (void *)func);
	func();
	return 0;
}
