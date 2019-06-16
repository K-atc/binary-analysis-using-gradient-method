#include <stdio.h>
#include <string.h>
#include <elf.h>

#define IS_ELF(h) (h->e_ident[0] == 0x7f && h->e_ident[1] == 'E' && h->e_ident[2] == 'L' && h->e_ident[3] == 'F')

int main() {
    // Read header
    char head[sizeof(Elf32_Ehdr)];
    fgets(head, sizeof(Elf32_Ehdr), stdin);
    Elf32_Ehdr *e32hdr = (Elf32_Ehdr *) head;

    printf("{\"e_ident0\":%d,\"e_ident1\":%d,\"e_ident2\":%d,\"e_ident3\":%d,\"ei_class\":%d}\n", 
        e32hdr->e_ident[0], e32hdr->e_ident[1], e32hdr->e_ident[2], e32hdr->e_ident[3], e32hdr->e_ident[EI_CLASS]);
    
    // Check magic number
    if (!IS_ELF(e32hdr)) {
        printf("This is not ELF file\n");
    }

    // Check ELF bits
    if (e32hdr->e_ident[EI_CLASS] == ELFCLASS64) {
        printf("This is 64 bit ELF.\n");
    }
}