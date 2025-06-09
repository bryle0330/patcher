#ifndef ICO_H
#define ICO_H

#include <windows.h>
#include <stdint.h>

typedef struct {
    uint32_t original_rva;    
    uint32_t stub_rva;        
    uint32_t iat_rva;        
    uint8_t* stub_code;       
    size_t stub_size;         
} ImportStub;

typedef struct {
    HANDLE file_handle;
    HANDLE mapping_handle;
    uint8_t* mapped_base;
    uint32_t image_base;     
    IMAGE_DOS_HEADER* dos_header;
    IMAGE_NT_HEADERS* nt_headers;
    ImportStub* stubs;
    size_t stub_count;
    uint8_t* new_section;
    uint32_t new_section_rva;
} ICOContext;

static inline uint8_t* rva_to_raw(ICOContext* ctx, uint32_t rva) {
    IMAGE_SECTION_HEADER* secs = IMAGE_FIRST_SECTION(ctx->nt_headers);
    WORD n = ctx->nt_headers->FileHeader.NumberOfSections;
    for (WORD i = 0; i < n; i++) {
        uint32_t va  = secs[i].VirtualAddress;
        uint32_t sz  = secs[i].Misc.VirtualSize;
        uint32_t ptr = secs[i].PointerToRawData;
        if (rva >= va && rva < va + sz) {
            return ctx->mapped_base + ptr + (rva - va);
        }
    }
    return ctx->mapped_base + rva;
}

ICOContext* ico_init_context(const char* filepath);
void ico_free_context(ICOContext* ctx);
BOOL ico_parse_pe(ICOContext* ctx);

BOOL ico_generate_import_stubs(ICOContext* ctx);
BOOL ico_add_new_section(ICOContext* ctx, const char* section_name, uint32_t section_size);

BOOL ico_find_and_patch_calls(ICOContext* ctx);
BOOL ico_apply_changes(ICOContext* ctx);

#endif 