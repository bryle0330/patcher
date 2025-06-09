#include "ico.h"
#include <stdio.h>

static BOOL is_rva_in_import_table(ICOContext* ctx, uint32_t rva) {
    IMAGE_DATA_DIRECTORY* imp = &ctx->nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    return (rva >= imp->VirtualAddress && 
            rva < (imp->VirtualAddress + imp->Size));
}

static ImportStub* find_stub_for_rva(ICOContext* ctx, uint32_t rva) {
    for (size_t i = 0; i < ctx->stub_count; i++) {
        if (ctx->stubs[i].original_rva == rva) {
            return &ctx->stubs[i];
        }
    }
    return NULL;
}

BOOL ico_find_and_patch_calls(ICOContext* ctx) {
    if (!ctx || !ctx->nt_headers) return FALSE;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ctx->nt_headers);
    for (int s = 0; s < ctx->nt_headers->FileHeader.NumberOfSections; ++s) {
        IMAGE_SECTION_HEADER* sect = &sections[s];
        if (!(sect->Characteristics & IMAGE_SCN_CNT_CODE))
            continue;

        uint8_t* base = ctx->mapped_base + sect->PointerToRawData;
        uint32_t rvaBase = sect->VirtualAddress;
        uint32_t size = sect->Misc.VirtualSize;

        for (uint32_t off = 0; off + 6 <= size; ++off) {
            uint8_t* p = base + off;

            if (p[0] == 0xFF && p[1] == 0x15) {
                uint32_t iat_va = *(uint32_t*)(p + 2);
                uint32_t iat_rva = iat_va - ctx->image_base;
                
                printf("[DEBUG] Found FF15 at RVA 0x%08X, IAT RVA = 0x%08X\n", 
                       rvaBase + off, iat_rva);
                printf("[DBG] iat_va = 0x%08X, image_base = 0x%08X\n", iat_va, ctx->image_base);
            
                for (int i = 0; i < ctx->stub_count; ++i) {
                    printf("[DEBUG] Comparing with stub[%d].iat_rva = 0x%08X\n", 
                           i, ctx->stubs[i].iat_rva);
                    if (ctx->stubs[i].iat_rva == iat_rva) {
                        printf("[DBG] MATCH found: stub[%d] iat_rva=0x%08X\n", i, ctx->stubs[i].iat_rva);
                        uint32_t stub_va = ctx->image_base + ctx->stubs[i].stub_rva;
                        uint32_t call_va = ctx->image_base + (rvaBase + off);
                        int32_t rel32 = (int32_t)(stub_va - (call_va + 5));

                        DWORD oldProtect;
                        if (!VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                            printf("[ico_find_and_patch_calls] VirtualProtect failed\n");
                            goto next_offset;
                        }
                        p[0] = 0xE8;
                        *(int32_t*)(p + 1) = rel32;
                        p[5] = 0x90;
                        printf("[DBG] after write: %02X %02X %02X %02X %02X %02X\n",
                               p[0], p[1], p[2], p[3], p[4], p[5]);
                        VirtualProtect(p, 6, oldProtect, &oldProtect);

                        printf("[patched] 0x%08X: FF15 → E8 %08X 90\n",
                               rvaBase + off, rel32);
                        goto next_offset;
                    }
                }
            }

            if (p[0] == 0xE8) {
                uint32_t target_rva = rvaBase + off + 5 + *(int32_t*)(p + 1);
                if (is_rva_in_import_table(ctx, target_rva)) {
                    ImportStub* stub = find_stub_for_rva(ctx, target_rva);
                    if (stub) {
                        uint32_t stub_va = ctx->image_base + stub->stub_rva;
                        uint32_t call_va = ctx->image_base + (rvaBase + off);
                        int32_t rel32 = (int32_t)(stub_va - (call_va + 5));

                        DWORD oldProtect;
                        if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                            printf("[ico_find_and_patch_calls] VirtualProtect failed\n");
                            goto next_offset;
                        }
                        *(int32_t*)(p + 1) = rel32;
                        VirtualProtect(p, 5, oldProtect, &oldProtect);

                        printf("[patched] 0x%08X: E8 → E8 %08X\n",
                               rvaBase + off, rel32);
                    }
                }
            }

        next_offset:;
        }
    }
    return TRUE;
}

BOOL ico_apply_changes(ICOContext* ctx) {
    printf("[ico_apply_changes] entered\n");
    if (!ctx || !ctx->mapped_base) return FALSE;

    if (!FlushViewOfFile(ctx->mapped_base, 0)) {
        printf("[ico_apply_changes] FlushViewOfFile failed\n");
        return FALSE;
    }

    printf("[ico_apply_changes] successfully flushed changes to disk\n");
    return TRUE;
}