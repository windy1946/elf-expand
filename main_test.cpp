#include <iostream>
#include "expand_elf.h"

int main(){
    const char* input_so = "libtest.so";
    const char* output_so = "libtest-o.so";
    expand_elf elf(input_so, output_so);

    elf.expand(0x4000);
    
    return 0;
}