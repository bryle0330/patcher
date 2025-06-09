#include "ico.h"
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#define XOR_KEY 0x42

static uint8_t x86_stub_template[] = {
    0x60,                   
    0xB8, 0x00, 0x00, 0x00, 0x00,  
    0x34, XOR_KEY,        
    0x89, 0x44, 0x24, 0x20,
    0x61,                   
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00  
};

static uint8_t x64_stub_template[] = {
    0x50,                   
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x48, 0x34, XOR_KEY,    
    0x48, 0x89, 0x44, 0x24, 0x08,  
    0x58,                   
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00  
};

static uint8_t generate_random_byte() {
    static int initialized = 0;
    if (!initialized) {
        srand((unsigned int)time(NULL));
        initialized = 1;
    }
    return (uint8_t)(rand() & 0xFF);
}

static ImportStub create_import_stub(ICOContext* ctx, uint32_t original_rva, uint32_t iat_rva, BOOL is_x64) {
    ImportStub stub = {0};
    stub.original_rva = original_rva;

    uint8_t* template_code = is_x64 ? x64_stub_template : x86_stub_template;
    size_t template_size = is_x64 ? sizeof(x64_stub_template) : sizeof(x86_stub_template);

    stub.stub_code = (uint8_t*)malloc(template_size + 1);  
    if (!stub.stub_code) return stub;

    memcpy(stub.stub_code, template_code, template_size);
    stub.stub_size = template_size + 1;

    uint32_t encrypted_rva = original_rva ^ XOR_KEY;

    if (is_x64) {
        *(uint64_t*)(stub.stub_code + 3) = encrypted_rva;
        *(uint32_t*)(stub.stub_code + template_size - 4) = iat_rva;
    } else {
        *(uint32_t*)(stub.stub_code + 1) = encrypted_rva;
        *(uint32_t*)(stub.stub_code + template_size - 4) = iat_rva;
    }

    stub.iat_rva = iat_rva;

    stub.stub_code[template_size] = generate_random_byte();

    return stub;
}

BOOL ico_generate_import_stubs(ICOContext* ctx) {
    printf("[ico_generate_import_stubs] entered\n");
    if (!ctx || !ctx->nt_headers || !ctx->new_section) return FALSE;

    BOOL is_x64 = ctx->nt_headers->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
    WORD magic = ctx->nt_headers->OptionalHeader.Magic;

    DWORD import_rva, import_size;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)ctx->nt_headers;
        import_rva  = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        import_size = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)ctx->nt_headers;
        import_rva  = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        import_size = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    printf("[imports] RVA=0x%016I64x Size=0x%016I64x\n",
           (unsigned long long)import_rva,
           (unsigned long long)import_size);

    if (import_rva == 0 || import_size == 0) {
        printf("Failed to generate import stubs\n");
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR import_desc =
        (PIMAGE_IMPORT_DESCRIPTOR)rva_to_raw(ctx, import_rva);

    size_t total_imports = 0;
    for (PIMAGE_IMPORT_DESCRIPTOR desc = import_desc; desc->Name; desc++) {
        PIMAGE_THUNK_DATA nameThunk = (PIMAGE_THUNK_DATA)rva_to_raw(ctx, desc->OriginalFirstThunk);
        while (nameThunk->u1.AddressOfData) {
            total_imports++;
            nameThunk++;
        }
    }

    printf("[stub gen] total_imports = %zu; new_section_rva = 0x%08x\n", 
           total_imports, ctx->new_section_rva);

    ctx->stubs = (ImportStub*)calloc(total_imports, sizeof(ImportStub));
    if (!ctx->stubs) {
        printf("Failed to allocate stub array\n");
        return FALSE;
    }

    uint32_t current_rva = ctx->new_section_rva;
    size_t stub_index = 0;
    printf("[stubs] starting stub generation at RVA 0x%08x\n", current_rva);

    for (PIMAGE_IMPORT_DESCRIPTOR desc = import_desc; desc->Name; desc++) {
        const char* dllName = (const char*)rva_to_raw(ctx, desc->Name);
        printf("[import] DLL: %s\n", dllName);

        PIMAGE_THUNK_DATA nameThunk = (PIMAGE_THUNK_DATA)rva_to_raw(ctx, desc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA iatThunk = (PIMAGE_THUNK_DATA)rva_to_raw(ctx, desc->FirstThunk);
        size_t idx = 0;

        while (nameThunk->u1.AddressOfData) {
            uint32_t func_rva;
            if (nameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                func_rva = (uint32_t)(nameThunk->u1.Ordinal & 0xFFFF);
            } else {
                PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)
                    rva_to_raw(ctx, nameThunk->u1.AddressOfData);
                func_rva = (uint32_t)(uintptr_t)ibn->Name;
            }

            uint32_t iat_rva = desc->FirstThunk + (uint32_t)(idx * sizeof(IMAGE_THUNK_DATA));
            printf("  [thunk] IAT-entry @ RVA 0x%08x → Function RVA 0x%08x\n", 
                   iat_rva, func_rva);

            ImportStub stub = create_import_stub(ctx, func_rva, iat_rva, is_x64);
            if (!stub.stub_code) {
                return FALSE;
            }

            printf("[stub #%zu] original RVA=0x%08x → writing %zu bytes at new raw offset 0x%08x\n",
                   stub_index, stub.original_rva, stub.stub_size,
                   (uint32_t)(current_rva - ctx->new_section_rva));

            memcpy(ctx->new_section + (current_rva - ctx->new_section_rva),
                   stub.stub_code, stub.stub_size);
            stub.stub_rva = current_rva;
            ctx->stubs[stub_index++] = stub;

            current_rva += stub.stub_size;
            nameThunk++;
            iatThunk++;
            idx++;
        }
    }

    ctx->stub_count = stub_index;

    printf("\n[stub list] Generated %zu stubs:\n", ctx->stub_count);
    for (size_t i = 0; i < ctx->stub_count; i++) {
        printf("  stub[%2zu] iat_rva=0x%08x  orig_rva=0x%08x\n",
               i, ctx->stubs[i].iat_rva, ctx->stubs[i].original_rva);
    }

    if (ctx->stub_count > 0) {
        printf("[stub gen] first stub bytes: ");
        for (size_t i = 0; i < (ctx->stubs[0].stub_size < 16 ? ctx->stubs[0].stub_size : 16); i++) {
            printf("%02x ", ctx->new_section[i]);
        }
        printf("\n");
    }
    return TRUE;
}