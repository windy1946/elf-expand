#include "elf_utils.h"
#include "log.h"
#include "elf.h"
#include <cstring>
#include<stdio.h>
#include<sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>

elf_utils::elf_utils(const std::string &name) : filename(name) {
    this->arch = ARCH_NONE;
    this->type = PLATFORM_NONE;
    this->mode = ARCH_BIT_NONE;
    this->file_buffer = NULL;
#if (defined(__MINGW32__) || defined(__MINGW64__))
    this->fd = open(name.c_str(), O_RDWR | O_BINARY, 0666);
#else
    this->fd = open(name.c_str(), O_RDWR, 0666);
#endif
    size_t readbyte = 0;
    this->file_buffer = read(0, -1, readbyte);
    this->fileLen = readbyte;

    init();
}

elf_utils::~elf_utils() {
    if (this->fd > 0) {
        close(this->fd);
        this->fd = 0;
    }
}

void elf_utils::init() {
    if(this->file_buffer != NULL){
        uint8_t* e_ident = (uint8_t*)this->file_buffer;
        if(e_ident[EI_CLASS] == ELFCLASS32){
            this->mode = ARCH_BIT_32;
        }else{
            this->mode = ARCH_BIT_64;
        }
    }
}


//misc
off_t elf_utils::search_bytes(const char* buffer, size_t buff_len, const char *str, size_t str_len) {
    if (buff_len < str_len) {
        return (off_t)-1;
    }
    off_t i = 0;
    for (; i < (off_t)(buff_len - str_len) + 1; i++) {
        if (memcmp(buffer + i, str, str_len) == 0) {
            return i;
        }
    }
    return (off_t)-1;
}



uint8_t* elf_utils::read(off_t offset, size_t len, size_t &readbytes) {
    if (this->fd <= 0) {
        LOGE("fd is invalid");
        return NULL;
    }

    size_t fl_len = lseek(this->fd, 0, SEEK_END);
    if (fl_len == 0) {
        LOGE("file size is 0");
        return NULL;
    }

    if (len == (size_t)-1) {
        len = fl_len;
    }

    if (offset + len > fl_len) {
        LOGE("offset is beyond file size.");
        //LOGD("offset:%xl, len:%lx, fl_leln:%lx", offset, len, fl_len);
        return NULL;
    }

    lseek(this->fd, offset, SEEK_SET);

    uint8_t *buffer = new uint8_t[len]();
    if (len != (size_t)::read(this->fd, (void*)buffer, len)) {
        delete [] buffer;
        return NULL;
    }
    readbytes = len;

    return buffer;

}

size_t elf_utils::write(uint8_t *buffer, size_t len, off_t offset) {
    if (this->fd <= 0) {
        return 0;
    }

    size_t fl_len = lseek(this->fd, 0, SEEK_END);
    if (offset + len > fl_len) {
        return 0;
    }

    lseek(this->fd, offset, SEEK_SET);

    if (len != (size_t)::write(this->fd, buffer, len)) {
        return 0;
    }

    return len;
}

void* elf_utils::get_shdr(uint8_t* buffer, int index){
    if(this->mode == ARCH_BIT_32){
        Elf32_Ehdr* m_Elf32Header = (Elf32_Ehdr*)buffer;
        if(m_Elf32Header->e_shnum <= index){
            return NULL;
        }
        Elf32_Shdr* sechdraddr = (Elf32_Shdr*)((unsigned char*)m_Elf32Header + m_Elf32Header->e_shoff);
        return &sechdraddr[index];
    }else if(this->mode == ARCH_BIT_64){
        Elf64_Ehdr* m_Elf64Header = (Elf64_Ehdr*)buffer;
        if(m_Elf64Header->e_shnum <= index){
            return NULL;
        }
        Elf64_Shdr* sechdraddr = (Elf64_Shdr*)((unsigned char*)m_Elf64Header + m_Elf64Header->e_shoff);
        return &sechdraddr[index];
    }
    return NULL;
}

void* elf_utils::get_shdr_by_type(uint8_t* buffer, int shdr_type){
    if(buffer == NULL){
        return NULL;
    }

    if (this->mode == ARCH_BIT_32) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)buffer;
        Elf32_Shdr* sechdraddr = (Elf32_Shdr*)(buffer + ehdr->e_shoff);
        for (int i=0; i<ehdr->e_shnum; i++) {
            if((Elf32_Word)shdr_type == sechdraddr[i].sh_type){
                return &sechdraddr[i];
            }
        }
    } else if (this->mode == ARCH_BIT_64) {
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)buffer;
        Elf64_Shdr* sechdraddr = (Elf64_Shdr*)(buffer + ehdr->e_shoff);
        for (int i = 0; i < ehdr->e_shnum; i++) {
            if((Elf64_Word)shdr_type == sechdraddr[i].sh_type){
                return &sechdraddr[i];
            }
        }
    }

    return NULL;
}
void* elf_utils::get_shdr(const std::string & name) {
    if(this->file_buffer == NULL){
        return NULL;
    }

    if (this->mode == ARCH_BIT_32) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)this->file_buffer;
        Elf32_Shdr* sechdraddr = (Elf32_Shdr*)(this->file_buffer + ehdr->e_shoff);

        Elf32_Shdr* secstrhdr =  &sechdraddr[ehdr->e_shstrndx];
        //LOGD("secname:%s, secnum : %d, shstrndx : %d", secname, ehdr->e_shnum, ehdr->e_shstrndx);
        for (int i=0; i<ehdr->e_shnum; i++) {
            //LOGD("i: %d, offset:%x", i, sechdraddr[i].sh_offset);
            const char* cur_name =  (char*)(sechdraddr[i].sh_name + secstrhdr->sh_offset + this->file_buffer);
            //LOGD("secname : %s", name);
            if(strcmp(name.c_str(), cur_name) == 0){
                return &sechdraddr[i];
            }
        }
    } else if (this->mode == ARCH_BIT_64) {
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)this->file_buffer;
        Elf64_Shdr* sechdraddr = (Elf64_Shdr*)(this->file_buffer + ehdr->e_shoff);
        Elf64_Shdr* secstrhdr =  &sechdraddr[ehdr->e_shstrndx];
        //LOGD("secnum : %d", elf64Header->e_shnum);
        for (int i = 0; i < ehdr->e_shnum; i++) {
            char* cur_name =  (char*)(sechdraddr[i].sh_name + secstrhdr->sh_offset + this->file_buffer);
            //LOGD("secname : %s", name);
            if (strcmp(name.c_str(), cur_name) == 0) {
                return &sechdraddr[i];
            }
        }
    }

    return NULL;
}
 
void* elf_utils::get_shdr(uint8_t* buffer, const std::string & name) {
    if(buffer == NULL){
        return NULL;
    }

    if (this->mode == ARCH_BIT_32) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)buffer;
        Elf32_Shdr* sechdraddr = (Elf32_Shdr*)(buffer + ehdr->e_shoff);

        Elf32_Shdr* secstrhdr =  &sechdraddr[ehdr->e_shstrndx];
        //LOGD("secname:%s, secnum : %d, shstrndx : %d", secname, ehdr->e_shnum, ehdr->e_shstrndx);
        for (int i=0; i<ehdr->e_shnum; i++) {
            //LOGD("i: %d, offset:%x", i, sechdraddr[i].sh_offset);
            const char* cur_name =  (char*)(sechdraddr[i].sh_name + secstrhdr->sh_offset + buffer);
            //LOGD("secname : %s", name);
            if(strcmp(name.c_str(), cur_name) == 0){
                return &sechdraddr[i];
            }
        }
    } else if (this->mode == ARCH_BIT_64) {
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)buffer;
        Elf64_Shdr* sechdraddr = (Elf64_Shdr*)(buffer + ehdr->e_shoff);
        Elf64_Shdr* secstrhdr =  &sechdraddr[ehdr->e_shstrndx];
        //LOGD("secnum : %d", elf64Header->e_shnum);
        for (int i = 0; i < ehdr->e_shnum; i++) {
            char* cur_name =  (char*)(sechdraddr[i].sh_name + secstrhdr->sh_offset + buffer);
            //LOGD("secname : %s", name);
            if (strcmp(name.c_str(), cur_name) == 0) {
                return &sechdraddr[i];
            }
        }
    }

    return NULL;
}

void* elf_utils::get_shdrs(uint8_t* buffer, int& shnum){
    if(buffer == NULL){
        return NULL;
    }

    if (this->mode == ARCH_BIT_32) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)buffer;
        Elf32_Shdr* sechdraddr = (Elf32_Shdr*)(buffer + ehdr->e_shoff);
        shnum = ehdr->e_shnum;
        
        return sechdraddr;
    } else if (this->mode == ARCH_BIT_64) {
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)buffer;
        Elf64_Shdr* sechdraddr = (Elf64_Shdr*)(buffer + ehdr->e_shoff);
        shnum = ehdr->e_shnum;

        return sechdraddr;
    }

    return NULL;
}



void* elf_utils::get_phdr(uint8_t* buffer, int& phnum){
        phnum = 0;
    if(this->mode == ARCH_BIT_32){
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)buffer;
        phnum = ehdr->e_phnum;
        Elf32_Phdr* phdr = (Elf32_Phdr*)(buffer + ehdr->e_phoff);

        return phdr;
    }else if(this->mode == ARCH_BIT_64){
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)buffer;
        //LOGD("phoff:%ld", ehdr->e_phoff);
        phnum = ehdr->e_phnum;
        Elf64_Phdr* phdr = (Elf64_Phdr*)(buffer + ehdr->e_phoff);
        //LOGD("type:%d", phdr[0].p_type);
        return phdr;
    }
    return NULL;
}



unsigned char* elf_utils::get_buffer(){
    return this->file_buffer;
}


size_t elf_utils::get_file_size(){
    return this->fileLen;
}

