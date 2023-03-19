#include <fcntl.h>
#include <elf.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>


const unsigned char ELF_IDENT[] = {0x7f, 'E', 'L', 'F', ELFCLASS64, ELFDATA2LSB, EV_CURRENT};

typedef Elf64_Ehdr ElfHeader;
typedef Elf64_Shdr ElfSection;
typedef Elf64_Sym  ElfSymbol;

typedef struct {
    char* perf_start;
    char* perf_top;
    char* entry;
    char* stride;
    char* type_offset;
    char* field_offset;
    char* address_offset;
} VMSymbols;

typedef struct {
    unsigned int magic;
    unsigned char byte_order;
    unsigned char major_version;
    unsigned char minor_version;
    unsigned char accessible;
    unsigned int used;
    unsigned int overflow;
    unsigned long long mod_time_stamp;
    unsigned int entry_offset;
    unsigned int num_entries;
} PerfData;

typedef struct {
    unsigned int entry_length;
    unsigned int name_offset;
    unsigned int vector_length;
    unsigned char data_type;
    unsigned char flags;
    unsigned char data_units;
    unsigned char data_variability;
    unsigned int data_offset;
} PerfDataEntry;


static int pid;

static int error(const char* msg) {
    printf("%s\n", msg);
    return 1;
}

// Returns the full path and the base address of libjvm.so in the target process
static char* locate_libjvm(char* jvm_path) {
    char maps[64];
    snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
    FILE* f = fopen(maps, "r");
    if (f == NULL) {
        return NULL;
    }

    char* base_addr = NULL;
    char* line = NULL;
    size_t line_len = 0;

    ssize_t n;
    while ((n = getline(&line, &line_len, f)) > 0) {
        // Remove newline
        line[n - 1] = 0;

        if (n >= 11 && strcmp(line + n - 11, "/libjvm.so") == 0) {
            const char* addr = line;
            const char* end = strchr(addr, '-') + 1;
            const char* perm = strchr(end, ' ') + 1;
            const char* offs = strchr(perm, ' ') + 1;
            const char* dev = strchr(offs, ' ') + 1;
            const char* inode = strchr(dev, ' ') + 1;
            const char* file = strchr(inode, ' ');
            while (*file == ' ') file++;

            base_addr = (char*)(strtoul(addr, NULL, 16) - strtoul(offs, NULL, 16));
            strcpy(jvm_path, file);
            break;
        }
    }

    free(line);
    fclose(f);
    return base_addr;
}

static inline char* at(void* base, int offset) {
    return (char*)base + offset;
}

static ElfSection* elf_section_at(ElfHeader* ehdr, int index) {
    return (ElfSection*)at(ehdr, ehdr->e_shoff + index * ehdr->e_shentsize);
}

static ElfSection* elf_find_section(ElfHeader* ehdr, uint32_t type) {
    const char* section_names = at(ehdr, elf_section_at(ehdr, ehdr->e_shstrndx)->sh_offset);

    int i;
    for (i = 0; i < ehdr->e_shnum; i++) {
        ElfSection* section = elf_section_at(ehdr, i);
        if (section->sh_type == type) {
            return section;
        }
    }

    return NULL;
}

// Parses libjvm.so to find PerfMemory and VMStructs symbols
static int read_symbols(const char* file_name, char* base_addr, VMSymbols* vmsym) {
    int fd = open(file_name, O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    size_t length = lseek(fd, 0, SEEK_END);
    ElfHeader* ehdr = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (ehdr == MAP_FAILED) {
        return -1;
    }

    if (memcmp(ehdr->e_ident, ELF_IDENT, sizeof(ELF_IDENT)) != 0) {
        munmap(ehdr, length);
        return -1;
    }

    ElfSection* symtab;
    if ((symtab = elf_find_section(ehdr, SHT_SYMTAB)) == NULL &&
        (symtab = elf_find_section(ehdr, SHT_DYNSYM)) == NULL) {
        munmap(ehdr, length);
        return -1;
    }

    ElfSection* strtab = elf_section_at(ehdr, symtab->sh_link);
    const char* strings = at(ehdr, strtab->sh_offset);

    const char* symbols = at(ehdr, symtab->sh_offset);
    const char* symbols_end = symbols + symtab->sh_size;

    for (; symbols < symbols_end; symbols += symtab->sh_entsize) {
        ElfSymbol* sym = (ElfSymbol*)symbols;
        if (sym->st_name != 0 && sym->st_value != 0) {
            const char* name = strings + sym->st_name;
            if (strncmp(name, "_ZN10PerfMemory", 15) == 0) {
                if (strcmp(name, "_ZN10PerfMemory6_startE") == 0) {
                    vmsym->perf_start = base_addr + sym->st_value;
                } else if (strcmp(name, "_ZN10PerfMemory4_topE") == 0) {
                    vmsym->perf_top = base_addr + sym->st_value;
                }
            } else if (strncmp(name, "gHotSpotVMStruct", 16) == 0) {
                if (strcmp(name, "gHotSpotVMStructs") == 0) {
                    vmsym->entry = base_addr + sym->st_value;
                } else if (strcmp(name, "gHotSpotVMStructEntryArrayStride") == 0) {
                    vmsym->stride = base_addr + sym->st_value;
                } else if (strcmp(name, "gHotSpotVMStructEntryTypeNameOffset") == 0) {
                    vmsym->type_offset = base_addr + sym->st_value;
                } else if (strcmp(name, "gHotSpotVMStructEntryFieldNameOffset") == 0) {
                    vmsym->field_offset = base_addr + sym->st_value;
                } else if (strcmp(name, "gHotSpotVMStructEntryAddressOffset") == 0) {
                    vmsym->address_offset = base_addr + sym->st_value;
                }
            }
        }
    }

    munmap(ehdr, length);
    return 0;
}

// Helpers to read memory of the target JVM
static ssize_t vm_read(char* remote, void* local, size_t size) {
    struct iovec local_iov = {local, size};
    struct iovec remote_iov = {remote, size};
    return process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}

static char* vm_read_ptr(char* remote) {
    char* result;
    return vm_read(remote, &result, sizeof(result)) > 0 ? result : NULL;
}

static int vm_cmp(char* remote, const char* local, size_t size) {
    char tmp[64];
    return vm_read(remote, tmp, size) > 0 && memcmp(tmp, local, size) == 0;
}

// Looks for PerfMemory address in the target JVM using VMStructs
static int read_vmstructs(VMSymbols* vmsym, char** perfmem) {
    // Fast path: PerfMemory symbols are available in libjvm.so
    if (vmsym->perf_start != NULL && vmsym->perf_top != NULL) {
        perfmem[0] = vm_read_ptr(vmsym->perf_start);
        perfmem[1] = vm_read_ptr(vmsym->perf_top);
        return 0;
    }

    // Backup path: locate PerfMemory using VMStructs
    char* entry = vm_read_ptr(vmsym->entry);
    intptr_t stride = (intptr_t)vm_read_ptr(vmsym->stride);
    intptr_t type_offset = (intptr_t)vm_read_ptr(vmsym->type_offset);
    intptr_t field_offset = (intptr_t)vm_read_ptr(vmsym->field_offset);
    intptr_t address_offset = (intptr_t)vm_read_ptr(vmsym->address_offset);

    if (entry == NULL || stride == 0) {
        return -1;
    }

    while (1) {
        char* type = vm_read_ptr(entry + type_offset);
        char* field = vm_read_ptr(entry + field_offset);
        if (type == NULL || field == NULL) {
            return 0;
        }

        if (vm_cmp(type, "PerfMemory", 11)) {
            if (vm_cmp(field, "_start", 7)) {
                perfmem[0] = vm_read_ptr(vm_read_ptr(entry + address_offset));
            } else if (vm_cmp(field, "_top", 5)) {
                perfmem[1] = vm_read_ptr(vm_read_ptr(entry + address_offset));
            }
        }

        entry += stride;
    }
}

static PerfData* read_perf_data(char* perfmem, size_t size) {
    PerfData* result = malloc(size);
    if (result != NULL && vm_read(perfmem, result, size) <= 0) {
        free(result);
        return NULL;
    }
    return result;
}

static void print_all_counters(PerfData* perfdata) {
    PerfDataEntry* e = (PerfDataEntry*)at(perfdata, perfdata->entry_offset);
    int i;
    for (i = 0; i < perfdata->num_entries; i++) {
        if (e->data_type == 'B') {
            printf("%s=\"%s\"\n", at(e, e->name_offset), at(e, e->data_offset));
        } else if (e->data_type == 'J') {
            printf("%s=%lld\n", at(e, e->name_offset), *(long long*)at(e, e->data_offset));
        }
        e = (PerfDataEntry*)at(e, e->entry_length);
    }
}

static void print_counter(PerfData* perfdata, const char* name) {
    PerfDataEntry* e = (PerfDataEntry*)at(perfdata, perfdata->entry_offset);
    int i;
    for (i = 0; i < perfdata->num_entries; i++) {
        if (strcmp(name, at(e, e->name_offset)) == 0) {
            if (e->data_type == 'B') {
                printf("%s\n", at(e, e->data_offset));
            } else if (e->data_type == 'J') {
                printf("%lld\n", *(long long*)at(e, e->data_offset));
            }
            break;
        }
        e = (PerfDataEntry*)at(e, e->entry_length);
    }
}


int main(int argc, char** argv) {
    if (argc < 2 || (pid = atoi(argv[1])) <= 0) {
        return error("Usage: hsperf <pid> [<counter>...]");
    }

    char jvm_path[PATH_MAX];
    char* jvm_base = locate_libjvm(jvm_path);
    if (jvm_base == NULL) {
        return error("Could not locate loaded libjvm.so");
    }

    VMSymbols vmsym = {NULL};
    if (read_symbols(jvm_path, jvm_base, &vmsym) != 0) {
        return error("Failed to parse libjvm.so");
    }

    char* perfmem[2] = {NULL};
    if (read_vmstructs(&vmsym, perfmem) != 0) {
        return error("Failed to read VMStructs");
    }

    PerfData* perfdata = read_perf_data(perfmem[0], perfmem[1] - perfmem[0]);
    if (perfdata == NULL) {
        return error("Failed to read PerfData");
    }

    if (argc == 2) {
        print_all_counters(perfdata);
    } else {
        while (--argc > 1) {
            print_counter(perfdata, (++argv)[1]);
        }
    }

    free(perfdata);
    return 0;
}
