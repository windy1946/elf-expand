
#ifndef UPX_ELF_UTILS
#define UPX_ELF_UTILS

#include <iostream>
#include <vector>


enum arch_type {
    ARCH_NONE, ARCH_ARM, ARCH_THUMB, ARCH_THUMB2, ARCH_ARM64, ARCH_X86, ARCH_X86_64
};
enum platform {
    PLATFORM_NONE, PLATFORM_ARM, PLATFORM_ARM64, PLATFORM_X86, PLATFORM_X86_64
};
enum arch_bit {
    ARCH_BIT_NONE, ARCH_BIT_32, ARCH_BIT_64
};

class elf_utils{
private:
    std::string filename;
    uint8_t *file_buffer;
    size_t fileLen;
    int fd;
    enum arch_bit mode;
    platform type;
    arch_type arch;
    
public:
    explicit elf_utils(const std::string& name);
    ~elf_utils();

    platform get_type(){return type;};
    arch_type get_arch(){return arch;};
    arch_bit get_mode(){return mode;};

    // ELF manipulation
    void* get_shdr(uint8_t* buffer, const std::string & name);
    void* get_shdr(uint8_t* buffer, int index);
    void* get_shdr_by_type(uint8_t* buffer, int type);
    void* get_shdrs(uint8_t* buffer, int& shnum);
    void* get_shdr(const std::string & name);

    char* get_section_name(uint8_t* buffer, int nameoff);
    void* get_phdr(uint8_t* buffer, int& phnum);

    // IO
    unsigned char* read(off_t offset, size_t len, size_t &readbytes);
    size_t write(uint8_t *buffer, size_t len, off_t offset);
    unsigned char* get_buffer();
    size_t get_file_size();
    // functional
    static off_t search_bytes(const char* buffer, size_t buff_len, const char *str, size_t str_len);
private:
    void init();
};

#endif