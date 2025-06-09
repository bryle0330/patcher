#include "ico.h"
#include <stdio.h>
#include <stdlib.h>

ICOContext* ico_init_context(const char* filepath) {
    ICOContext* ctx = (ICOContext*)calloc(1, sizeof(ICOContext));
    if (!ctx) return NULL;

    ctx->file_handle = CreateFileA(
        filepath,
        GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (ctx->file_handle == INVALID_HANDLE_VALUE) {
        free(ctx);
        return NULL;
    }

    ctx->mapping_handle = CreateFileMappingA(
        ctx->file_handle,
        NULL,
        PAGE_EXECUTE_READWRITE,
        0,
        0,
        NULL
    );

    if (!ctx->mapping_handle) {
        CloseHandle(ctx->file_handle);
        free(ctx);
        return NULL;
    }

    ctx->mapped_base = (uint8_t*)MapViewOfFile(
        ctx->mapping_handle,
        FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE,
        0,
        0,
        0
    );

    if (!ctx->mapped_base) {
        CloseHandle(ctx->mapping_handle);
        CloseHandle(ctx->file_handle);
        free(ctx);
        return NULL;
    }

    return ctx;
}

void ico_free_context(ICOContext* ctx) {
    if (!ctx) return;

    if (ctx->mapped_base) {
        FlushViewOfFile(ctx->mapped_base, 0);
        UnmapViewOfFile(ctx->mapped_base);
    }

    if (ctx->mapping_handle) {
        CloseHandle(ctx->mapping_handle);
    }

    if (ctx->file_handle) {
        CloseHandle(ctx->file_handle);
    }

    if (ctx->stubs) {
        for (size_t i = 0; i < ctx->stub_count; i++) {
            free(ctx->stubs[i].stub_code);
        }
        free(ctx->stubs);
    }

    free(ctx);
}

BOOL ico_parse_pe(ICOContext* ctx) {
    printf("[ico_parse_pe] entered\n");
    if (!ctx || !ctx->mapped_base) return FALSE;

    ctx->dos_header = (IMAGE_DOS_HEADER*)ctx->mapped_base;
    if (ctx->dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    ctx->nt_headers = (IMAGE_NT_HEADERS*)(ctx->mapped_base + ctx->dos_header->e_lfanew);
    if (ctx->nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    WORD magic = ctx->nt_headers->OptionalHeader.Magic;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)ctx->nt_headers;
        ctx->image_base = nt32->OptionalHeader.ImageBase;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt_headers;
        ctx->image_base = (uint32_t)nt64->OptionalHeader.ImageBase;
    }
    else {
        printf("[!] Unknown optional header magic: 0x%04X\n", magic);
        return FALSE;
    }

    WORD machine = ctx->nt_headers->FileHeader.Machine;
    printf("[DBG] image_base = 0x%08X\n", ctx->image_base);
    if (machine != IMAGE_FILE_MACHINE_I386 && machine != IMAGE_FILE_MACHINE_AMD64) {
        return FALSE;
    }

    return TRUE;
}

BOOL ico_add_new_section(ICOContext* ctx, const char* section_name, uint32_t section_size) {
    printf("[ico_add_new_section] entered\n");
    if (!ctx || !ctx->nt_headers) return FALSE;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ctx->nt_headers);
    WORD num_sections = ctx->nt_headers->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* new_section = &sections[num_sections];

    strncpy_s((char*)new_section->Name, IMAGE_SIZEOF_SHORT_NAME, section_name, _TRUNCATE);

    DWORD align_mask = ctx->nt_headers->OptionalHeader.SectionAlignment - 1;
    DWORD file_align_mask = ctx->nt_headers->OptionalHeader.FileAlignment - 1;

    new_section->Misc.VirtualSize = (section_size + align_mask) & ~align_mask;
    new_section->VirtualAddress = (sections[num_sections - 1].VirtualAddress +
                                 sections[num_sections - 1].Misc.VirtualSize +
                                 align_mask) & ~align_mask;
    new_section->SizeOfRawData = (section_size + file_align_mask) & ~file_align_mask;
    new_section->PointerToRawData = (sections[num_sections - 1].PointerToRawData +
                                   sections[num_sections - 1].SizeOfRawData +
                                   file_align_mask) & ~file_align_mask;
    new_section->Characteristics = IMAGE_SCN_MEM_EXECUTE |
                                 IMAGE_SCN_MEM_READ |
                                 IMAGE_SCN_CNT_CODE;

    ctx->nt_headers->FileHeader.NumberOfSections++;
    ctx->nt_headers->OptionalHeader.SizeOfImage = new_section->VirtualAddress + new_section->Misc.VirtualSize;

    DWORD newRawEnd = new_section->PointerToRawData + new_section->SizeOfRawData;
    SetFilePointer(ctx->file_handle, newRawEnd, NULL, FILE_BEGIN);
    if (!SetEndOfFile(ctx->file_handle)) {
        printf("[ico_add_new_section] failed to extend file to 0x%08x\n", newRawEnd);
        return FALSE;
    }

    UnmapViewOfFile(ctx->mapped_base);
    CloseHandle(ctx->mapping_handle);
    ctx->mapping_handle = CreateFileMappingA(ctx->file_handle, NULL, PAGE_EXECUTE_READWRITE, 0, 0, NULL);
    if (!ctx->mapping_handle) {
        printf("[ico_add_new_section] failed to create new file mapping\n");
        return FALSE;
    }
    ctx->mapped_base = (uint8_t*)MapViewOfFile(ctx->mapping_handle, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);
    if (!ctx->mapped_base) {
        printf("[ico_add_new_section] failed to map new view\n");
        CloseHandle(ctx->mapping_handle);
        return FALSE;
    }

    ctx->dos_header = (IMAGE_DOS_HEADER*)ctx->mapped_base;
    ctx->nt_headers = (IMAGE_NT_HEADERS*)(ctx->mapped_base + ctx->dos_header->e_lfanew);
    printf("[DBG] remapped_base = %p; dos->e_lfanew = 0x%X\n",
           ctx->mapped_base,
           ctx->dos_header->e_lfanew);

    ctx->new_section = ctx->mapped_base + new_section->PointerToRawData;
    ctx->new_section_rva = new_section->VirtualAddress;

    return TRUE;
}