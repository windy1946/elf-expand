#include "expand_elf.h"
#include <stdio.h>

int main(int argc, char **argv){
	if (argc < 4) {
		printf("usage %s <input_so> <output_so> <n_expand_hex>\n", argv[0]);
		return -1;
	}
    const char* input_so = argv[1];
    const char* output_so = argv[2];
    expand_elf elf(input_so, output_so);
	const char *str_n_expand = argv[3];
	int n_expand = strtol(str_n_expand, 0, 16);
    elf.expand(n_expand);
    
    return 0;
}
