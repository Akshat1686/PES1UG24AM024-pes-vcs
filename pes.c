#include "pes.h"
#include "index.h"
#include "commit.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

// Forward declarations for object.c utilities
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── PROVIDED: cmd_init ───────────────────────────────────────────────────────

void cmd_init(void) {
    // Create .pes/ directory structure
    mkdir(PES_DIR, 0755);
    mkdir(OBJECTS_DIR, 0755);
    mkdir(".pes/refs", 0755);
    mkdir(REFS_DIR, 0755);

    // Write HEAD pointing to refs/heads/main
    FILE *f = fopen(HEAD_FILE, "w");
    if (f) {
        fprintf(f, "ref: refs/heads/main\n");
        fclose(f);
    }

    printf("Initialized empty PES repository in .pes/\n");
}

// ─── PROVIDED: cmd_add ───────────────────────────────────────────────────────

void cmd_add(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: pes add <file>...\n");
        return;
    }

    Index index;
    index.count = 0;
    if (index_load(&index) != 0) {
        fprintf(stderr, "error: failed to load index\n");
        return;
    }

    for (int i = 2; i < argc; i++) {
        if (index_add(&index, argv[i]) != 0) {
            fprintf(stderr, "error: failed to stage '%s'\n", argv[i]);
        } else {
            printf("staged: %s\n", argv[i]);
        }
    }
}

// ─── PROVIDED: cmd_status ────────────────────────────────────────────────────

void cmd_status(void) {
    Index index;
    index.count = 0;
    if (index_load(&index) != 0) {
        fprintf(stderr, "error: failed to load index\n");
        return;
    }
    index_status(&index);
}

// ─── IMPLEMENTED: cmd_commit (Phase 4) ───────────────────────────────────────

// Walk callback for cmd_log — prints one commit
static void print_commit(const ObjectID *id, const Commit *c, void *ctx) {
    (void)ctx;
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    printf("commit %s\n", hex);
    printf("Author: %s\n", c->author);
    printf("Date:   %llu\n", (unsigned long long)c->timestamp);
    printf("\n    %s\n\n", c->message);
}

void cmd_log(void) {
    if (commit_walk(print_commit, NULL) != 0) {
        fprintf(stderr, "error: no commits yet\n");
    }
}

// Parse -m <message> and create a commit.
void cmd_commit(int argc, char *argv[]) {
    // Find the -m flag and its argument
    const char *message = NULL;
    for (int i = 2; i < argc - 1; i++) {
        if (strcmp(argv[i], "-m") == 0) {
            message = argv[i + 1];
            break;
        }
    }

    if (!message) {
        fprintf(stderr, "error: commit requires a message (-m \"message\")\n");
        return;
    }

    ObjectID commit_id;
    if (commit_create(message, &commit_id) != 0) {
        fprintf(stderr, "error: commit failed\n");
        return;
    }

    // Print: Committed: <first-12-hex-chars>... <message>
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&commit_id, hex);
    hex[12] = '\0'; // truncate to first 12 chars
    printf("Committed: %s... %s\n", hex, message);
}

// ─── PROVIDED: Phase 5 Command Wrappers ─────────────────────────────────────

void cmd_branch(int argc, char *argv[]) {
    if (argc == 2) {
        branch_list();
    } else if (argc == 3) {
        if (branch_create(argv[2]) == 0) {
            printf("Created branch '%s'\n", argv[2]);
        } else {
            fprintf(stderr, "error: failed to create branch '%s'\n", argv[2]);
        }
    } else if (argc == 4 && strcmp(argv[2], "-d") == 0) {
        if (branch_delete(argv[3]) == 0) {
            printf("Deleted branch '%s'\n", argv[3]);
        } else {
            fprintf(stderr, "error: failed to delete branch '%s'\n", argv[3]);
        }
    } else {
        fprintf(stderr, "Usage:\n pes branch\n pes branch <n>\n pes branch -d <n>\n");
    }
}

void cmd_checkout(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: pes checkout <branch_or_commit>\n");
        return;
    }
    const char *target = argv[2];
    if (checkout(target) == 0) {
        printf("Switched to '%s'\n", target);
    } else {
        fprintf(stderr, "error: checkout failed. Do you have uncommitted changes?\n");
    }
}

// ─── PROVIDED: Command dispatch ─────────────────────────────────────────────

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: pes <command> [args]\n");
        fprintf(stderr, "\nCommands:\n");
        fprintf(stderr, "  init                Create a new PES repository\n");
        fprintf(stderr, "  add <file>...       Stage files for commit\n");
        fprintf(stderr, "  status              Show working directory status\n");
        fprintf(stderr, "  commit -m <msg>     Create a commit from staged files\n");
        fprintf(stderr, "  log                 Show commit history\n");
        fprintf(stderr, "  branch              List, create, or delete branches\n");
        fprintf(stderr, "  checkout <ref>      Switch branches or restore working tree\n");
        return 1;
    }

    const char *cmd = argv[1];

    if      (strcmp(cmd, "init")     == 0) cmd_init();
    else if (strcmp(cmd, "add")      == 0) cmd_add(argc, argv);
    else if (strcmp(cmd, "status")   == 0) cmd_status();
    else if (strcmp(cmd, "commit")   == 0) cmd_commit(argc, argv);
    else if (strcmp(cmd, "log")      == 0) cmd_log();
    else if (strcmp(cmd, "branch")   == 0) cmd_branch(argc, argv);
    else if (strcmp(cmd, "checkout") == 0) cmd_checkout(argc, argv);
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        fprintf(stderr, "Run 'pes' with no arguments for usage.\n");
        return 1;
    }

    return 0;
}
