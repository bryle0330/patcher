#include <stdio.h>
#include <stdlib.h>
#include "ico.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pe_file>\n", argv[0]);
        return 1;
    }

    ICOContext* ctx = ico_init_context(argv[1]);
    if (!ctx) {
        printf("Failed to initialize ICO context\n");
        return 1;
    }

    if (!ico_parse_pe(ctx)) {
        printf("Failed to parse PE file\n");
        ico_free_context(ctx);
        return 1;
    }

    if (!ico_add_new_section(ctx, ".istub", 4096)) {
        printf("Failed to add new section\n");
        ico_free_context(ctx);
        return 1;
    }

    if (!ico_generate_import_stubs(ctx)) {
        printf("Failed to generate import stubs\n");
        ico_free_context(ctx);
        return 1;
    }

    if (!ico_find_and_patch_calls(ctx)) {
        printf("Failed to patch CALL instructions\n");
        ico_free_context(ctx);
        return 1;
    }

    if (!ico_apply_changes(ctx)) {
        printf("Failed to apply changes\n");
        ico_free_context(ctx);
        return 1;
    }

    printf("Successfully obfuscated import calls\n");
    ico_free_context(ctx);
    return 0;
}