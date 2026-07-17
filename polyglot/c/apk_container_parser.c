/*
 * polyglot/c/apk_container_parser.c
 * 
 * Android APK Static Security Analyzer — Container Parser Module
 * MASTG-aligned, zero dependencies, self-contained.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#define APK_MAGIC "\x45\x4c\x46"           /* ELF magic */
#define APK_MIN_SIZE 32                     /* Minimum valid APK size */

/* ELF Header Constants (64-bit, Android uses little-endian) */
#define ELF_CLASS_64 0x02
#define ELF_DATA_LITTLE 1
#define ELF_TYPE_EXEC 0x02
#define ET_EXEC 0x02
#define PT_LOAD 1
#define SHF_WRITE 0x01
#define SHF_ALLOC 0x02

/* ZIP Constants */
#define ZIP_MAGIC "\x50\x4b\x03\x04"        /* Local file header */
#define ZIP_CENTRAL_DIR_END "PK\005\006"    /* Central directory end */
#define ZIP_CEN_SIGNATURE 0x02014b50

/* AndroidX Resource Table Magic */
#define ANDROID_X_MAGIC "\x7f\x3e\x00\x00"

/* Directory entry types for APK resources */
typedef enum {
    DIR_TYPE_RESOURCES = 0x81,
    DIR_TYPE_RES_VALUES = 0x82,
    DIR_TYPE_RAW_DATA = 0x83,
    DIR_TYPE_DEX = 0x84,
    DIR_TYPE_ASSETS = 0x85,
    DIR_TYPE_NATIVE_LIBS = 0x86,
} ApkDirType;

/* APK Container Info Structure */
typedef struct {
    char elf_magic[4];
    uint16_t elf_class;
    uint16_t elf_data;
    uint32_t elf_type;
    uint64_t entry_point;
    
    char zip_magic[4];
    uint32_t num_local_files;
    uint32_t central_offset;
    uint32_t central_size;
    
    char package_name[256];
    uint32_t version_code;
    uint16_t version_name_major;
    uint16_t version_name_minor;
    
    uint64_t resources_offset;
    uint64_t dex_files_count;
    uint64_t native_libs_count;
    
    char* resource_strings;           /* Extracted strings buffer */
    size_t string_buffer_size;
    size_t string_buffer_used;
} ApkContainerInfo;

/* Forward declarations */
static int parse_elf_header(const void *data, ApkContainerInfo *info);
static int parse_zip_structure(const void *data, uint32_t offset, ApkContainerInfo *info);
static int extract_resource_strings(const void *data, ApkContainerInfo *info);
static int find_dex_files(const void *data, ApkContainerInfo *info);
static int find_native_libs(const void *data, ApkContainerInfo *info);

/*
 * Initialize the APK container info structure with defaults.
 */
static void apk_init_info(ApkContainerInfo *info) {
    memset(info, 0, sizeof(*info));
    
    /* Set default values */
    info->elf_class = ELF_CLASS_64;
    info->elf_data = ELF_DATA_LITTLE;
    info->elf_type = ET_EXEC;
    info->string_buffer_size = 1024 * 1024;  /* 1MB for strings */
}

/*
 * Parse the ELF header of the APK.
 * Returns 1 on success, 0 on failure.
 */
static int parse_elf_header(const void *data, ApkContainerInfo *info) {
    const unsigned char *elf = (const unsigned char *)data;
    
    /* Check minimum size for ELF header */
    if (sizeof(Elf64_Ehdr) > info->central_offset) {
        return 0;
    }
    
    /* Verify ELF magic */
    if (memcmp(elf, APK_MAGIC, 3) != 0) {
        return 0;
    }
    
    memcpy(info->elf_magic, elf, 4);
    info->elf_class = *(uint16_t *)(elf + 4);
    info->elf_data = *(uint16_t *)(elf + 5);
    info->elf_type = *(uint32_t *)(elf + 18);
    
    /* Verify it's a 64-bit little-endian executable */
    if (info->elf_class != ELF_CLASS_64 || 
        info->elf_data != ELF_DATA_LITTLE ||
        info->elf_type != ET_EXEC) {
        return 0;
    }
    
    /* Extract entry point for potential code analysis */
    info->entry_point = *(uint64_t *)(elf + 24);
    
    return 1;
}

/*
 * Parse the ZIP structure within the APK.
 * Returns 1 on success, 0 on failure.
 */
static int parse_zip_structure(const void *data, uint32_t offset, ApkContainerInfo *info) {
    const unsigned char *zip = (const unsigned char *)data;
    
    /* Check ZIP magic at the expected offset */
    if (offset >= info->central_offset || 
        memcmp(zip + offset, ZIP_MAGIC, 4) != 0) {
        return 0;
    }
    
    memcpy(info->zip_magic, zip + offset, 4);
    
    /* Parse central directory end record */
    const unsigned char *end = zip + info->central_offset - 22;
    
    if (info->central_offset < 22) {
        return 0;
    }
    
    uint32_t num_local_files = *(uint16_t *)(end - 4);
    uint32_t central_size = *(uint32_t *)(end - 18);
    uint32_t central_offset = *(uint32_t *)(end - 20);
    
    info->num_local_files = num_local_files;
    info->central_offset = central_offset;
    info->central_size = central_size;
    
    /* Verify we have enough data */
    if (info->central_offset + 46 > info->central_offset) {
        return 0;
    }
    
    /* Parse the first local file header to get package name */
    const unsigned char *local_header = zip + offset;
    
    uint32_t name_len = *(uint16_t *)(local_header + 26);
    if (name_len > 254) {
        return 0;
    }
    
    /* Extract package name from AndroidX resources */
    const unsigned char *res_start = local_header + 30 + name_len;
    
    while (res_start < zip + info->central_offset - 18 && 
           res_start[0] == 0x7f) {
        uint16_t type = *(uint16_t *)(res_start + 2);
        
        if (type == 0x3e) {  /* AndroidX resource table */
            const unsigned char *table = res_start + 4;
            
            /* Read package name from the first entry */
            uint16_t pkg_len = *(uint16_t *)(table + 2);
            if (pkg_len > 0 && pkg_len < 256) {
                memcpy(info->package_name, table + 4, pkg_len);
                info->package_name[pkg_len] = '\0';
            }
            
            /* Read version codes */
            info->version_code = *(uint32_t *)(table + 8);
            info->version_name_major = *(uint16_t *)(table + 12);
            info->version_name_minor = *(uint16_t *)(table + 14);
        }
        
        res_start += 4;  /* Move to next entry */
    }
    
    return 1;
}

/*
 * Extract strings from AndroidX resource tables.
 * Returns allocated buffer or NULL on failure.
 */
static int extract_resource_strings(const void *data, ApkContainerInfo *info) {
    const unsigned char *zip = (const unsigned char *)data;
    
    /* Start with the first local file header offset */
    uint32_t local_offset = 0x7f3e0000;  /* AndroidX resources start */
    
    if (local_offset >= info->central_offset) {
        return 0;
    }
    
    const unsigned char *res_start = zip + local_offset;
    
    while (res_start < zip + info->central_offset - 18 && 
           res_start[0] == 0x7f) {
        uint16_t type = *(uint16_t *)(res_start + 2);
        
        if (type == 0x3e) {  /* AndroidX resource table */
            const unsigned char *table = res_start + 4;
            
            /* Read number of entries */
            uint16_t num_entries = *(uint16_t *)(table + 28);
            
            if (num_entries > 0 && info->string_buffer_size - info->string_buffer_used >= num_entries * 64) {
                const unsigned char *entries = table + 30;
                
                for (uint16_t i = 0; i < num_entries && 
                     info->string_buffer_used < info->string_buffer_size; i++) {
                    uint16_t str_len = *(uint16_t *)(entries + 2);
                    
                    if (str_len > 0 && str_len < 512) {
                        /* Extract the string */
                        const unsigned char *str_ptr = entries + 4;
                        
                        if (info->string_buffer_used + str_len <= info->string_buffer_size) {
                            memcpy(info->resource_strings + info->string_buffer_used, 
                                   str_ptr, str_len);
                            info->string_buffer_used += str_len;
                            
                            /* Null-terminate */
                            info->resource_strings[info->string_buffer_used] = '\0';
                        }
                    }
                    
                    entries += 64;  /* Each entry is 64 bytes */
                }
            }
        }
        
        res_start += 4;  /* Move to next entry */
    }
    
    return 1;
}

/*
 * Find and count DEX files in the APK.
 */
static int find_dex_files(const void *data, ApkContainerInfo *info) {
    const unsigned char *zip = (const unsigned char *)data;
    
    uint32_t local_offset = 0x7f3e0000;  /* AndroidX resources start */
    
    if (local_offset >= info->central_offset) {
        return 0;
    }
    
    const unsigned char *res_start = zip + local_offset;
    
    while (res_start < zip + info->central_offset - 18 && 
           res_start[0] == 0x7f) {
        uint16_t type = *(uint16_t *)(res_start + 2);
        
        if (type == 0x3e) {  /* AndroidX resource table */
            const unsigned char *table = res_start + 4;
            
            /* Read number of entries */
            uint16_t num_entries = *(uint16_t *)(table + 28);
            
            if (num_entries > 0) {
                const unsigned char *entries = table + 30;
                
                for (uint16_t i = 0; i < num_entries; i++) {
                    uint16_t str_len = *(uint16_t *)(entries + 2);
                    
                    if (str_len > 0) {
                        const unsigned char *str_ptr = entries + 4;
                        
                        /* Check for DEX file patterns */
                        if (strstr((char *)str_ptr, ".dex") || 
                            strstr((char *)str_ptr, "classes.dex")) {
                            info->dex_files_count++;
                        }
                    }
                    
                    entries += 64;
                }
            }
        }
        
        res_start += 4;
    }
    
    return 1;
}

/*
 * Find and count native library directories.
 */
static int find_native_libs(const void *data, ApkContainerInfo *info) {
    const unsigned char *zip = (const unsigned char *)data;
    
    uint32_t local_offset = 0x7f3e0000;  /* AndroidX resources start */
    
    if (local_offset >= info->central_offset) {
        return 0;
    }
    
    const unsigned char *res_start = zip + local_offset;
    
    while (res_start < zip + info->central_offset - 18 && 
           res_start[0] == 0x7f) {
        uint16_t type = *(uint16_t *)(res_start + 2);
        
        if (type == 0x3e) {  /* AndroidX resource table */
            const unsigned char *table = res_start + 4;
            
            /* Read number of entries */
            uint16_t num_entries = *(uint16_t *)(table + 28);
            
            if (num_entries > 0) {
                const unsigned char *entries = table + 30;
                
                for (uint16_t i = 0; i < num_entries; i++) {
                    uint16_t str_len = *(uint16_t *)(entries + 2);
                    
                    if (str_len > 0) {
                        const unsigned char *str_ptr = entries + 4;
                        
                        /* Check for native library patterns */
                        if (strstr((char *)str_ptr, "lib/") || 
                            strstr((char *)str_ptr, ".so")) {
                            info->native_libs_count++;
                        }
                    }
                    
                    entries += 64;
                }
            }
        }
        
        res_start += 4;
    }
    
    return 1;
}

/*
 * Main parsing function - orchestrates all sub-parsers.
 */
int apk_parse_container(const char *apk_path, ApkContainerInfo *info) {
    FILE *fp = fopen(apk_path, "rb");
    
    if (!fp) {
        fprintf(stderr, "Error: Failed to open APK file '%s': %s\n", 
                apk_path, strerror(errno));
        return 0;
    }
    
    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size < APK_MIN_SIZE) {
        fprintf(stderr, "Error: APK too small (%ld bytes)\n", file_size);
        fclose(fp);
        return 0;
    }
    
    /* Allocate buffer for entire APK */
    unsigned char *buffer = malloc(file_size + 1);
    if (!buffer) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(fp);
        return 0;
    }
    
    /* Read entire file into memory */
    size_t bytes_read = fread(buffer, 1, file_size, fp);
    fclose(fp);
    
    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Error: Failed to read complete APK\n");
        free(buffer);
        return 0;
    }
    
    /* Initialize info structure */
    apk_init_info(info);
    
    /* Parse ELF header */
    if (!parse_elf_header(buffer, info)) {
        fprintf(stderr, "Warning: Invalid or non-ELF APK\n");
    } else {
        printf("  [ELF] Magic: %s\n", info->elf_magic);
        printf("  [ELF] Class: %d (64-bit)\n", info->elf_class);
        printf("  [ELF] Data: %d (Little-endian)\n", info->elf_data);
        printf("  [ELF] Type: %u\n", info->elf_type);
    }
    
    /* Parse ZIP structure */
    if (!parse_zip_structure(buffer, 0x7f3e0000, info)) {
        fprintf(stderr, "Warning: Invalid or corrupted ZIP structure\n");
    } else {
        printf("  [ZIP] Magic: %s\n", info->zip_magic);
        printf("  [ZIP] Local files: %u\n", info->num_local_files);
        printf("  [ZIP] Central offset: %u\n", info->central_offset);
    }
    
    /* Extract resource strings */
    if (!extract_resource_strings(buffer, info)) {
        fprintf(stderr, "Warning: Failed to extract resource strings\n");
    } else {
        printf("  [STRINGS] Buffer allocated: %zu MB\n", 
               info->string_buffer_size / (1024 * 1024));
        
        /* Print some sample strings */
        int samples = 5;
        for (