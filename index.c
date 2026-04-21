// index.c — Staging area implementation
//
// Text format of .pes/index (one entry per line, sorted by path):
//   <mode-octal> <64-char-hex-hash> <mtime-seconds> <size> <path>
//
// PROVIDED functions: index_find, index_remove, index_status
// IMPLEMENTED:        index_load, index_save, index_add
// ALSO DEFINED HERE:  tree_from_index (to avoid test_tree linker dependency on index.o)

#include "index.h"
#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

// Forward declarations for functions defined in object.c
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── PROVIDED ────────────────────────────────────────────────────────────────

IndexEntry* index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

int index_remove(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0) {
            int remaining = index->count - i - 1;
            if (remaining > 0)
                memmove(&index->entries[i], &index->entries[i + 1],
                        remaining * sizeof(IndexEntry));
            index->count--;
            return index_save(index);
        }
    }
    fprintf(stderr, "error: '%s' is not in the index\n", path);
    return -1;
}

int index_status(const Index *index) {
    printf("Staged changes:\n");
    int staged_count = 0;
    for (int i = 0; i < index->count; i++) {
        printf("  staged:     %s\n", index->entries[i].path);
        staged_count++;
    }
    if (staged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Unstaged changes:\n");
    int unstaged_count = 0;
    for (int i = 0; i < index->count; i++) {
        struct stat st;
        if (stat(index->entries[i].path, &st) != 0) {
            printf("  deleted:    %s\n", index->entries[i].path);
            unstaged_count++;
        } else {
            if (st.st_mtime != (time_t)index->entries[i].mtime_sec ||
                st.st_size  != (off_t)index->entries[i].size) {
                printf("  modified:   %s\n", index->entries[i].path);
                unstaged_count++;
            }
        }
    }
    if (unstaged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Untracked files:\n");
    int untracked_count = 0;
    DIR *dir = opendir(".");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            if (strcmp(ent->d_name, ".pes") == 0) continue;
            if (strcmp(ent->d_name, "pes") == 0) continue;
            if (strstr(ent->d_name, ".o") != NULL) continue;

            int is_tracked = 0;
            for (int i = 0; i < index->count; i++) {
                if (strcmp(index->entries[i].path, ent->d_name) == 0) {
                    is_tracked = 1;
                    break;
                }
            }
            if (!is_tracked) {
                struct stat st;
                if (stat(ent->d_name, &st) == 0 && S_ISREG(st.st_mode)) {
                    printf("  untracked:  %s\n", ent->d_name);
                    untracked_count++;
                }
            }
        }
        closedir(dir);
    }
    if (untracked_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    return 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

// Static global index used internally to avoid 5.6MB stack allocations.
// The Index struct is ~5.6MB (10000 entries × 568 bytes), which overflows
// the default 8MB stack when nested calls each allocate one on the stack.
// Making it static (BSS segment) sidesteps the stack limit entirely.
static Index g_index_buf;

static int compare_entries_by_path(const void *a, const void *b) {
    return strcmp(((const IndexEntry *)a)->path, ((const IndexEntry *)b)->path);
}

// Load the index from .pes/index into memory.
// If the file does not exist, initializes an empty index (not an error).
int index_load(Index *index) {
    index->count = 0;

    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) {
        // File doesn't exist yet — empty index is fine
        return 0;
    }

    char line[700];
    while (fgets(line, sizeof(line), f)) {
        if (index->count >= MAX_INDEX_ENTRIES) break;

        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') continue;

        IndexEntry *e = &index->entries[index->count];
        char hex[HASH_HEX_SIZE + 1];

        // Format: <mode-octal> <64-hex> <mtime> <size> <path>
        unsigned long long mtime_tmp;
        unsigned int size_tmp;
        unsigned int mode_tmp;
        if (sscanf(line, "%o %64s %llu %u %511s",
                   &mode_tmp, hex, &mtime_tmp, &size_tmp, e->path) != 5)
            continue;

        e->mode      = (uint32_t)mode_tmp;
        e->mtime_sec = (uint64_t)mtime_tmp;
        e->size      = (uint32_t)size_tmp;

        if (hex_to_hash(hex, &e->hash) != 0) continue;
        index->count++;
    }

    fclose(f);
    return 0;
}

// Save the index to .pes/index atomically (temp file + rename).
int index_save(const Index *index) {
    // Sort a copy by path — use the static buffer to avoid stack overflow
    g_index_buf = *index;
    qsort(g_index_buf.entries, g_index_buf.count,
          sizeof(IndexEntry), compare_entries_by_path);

    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", INDEX_FILE);

    FILE *f = fopen(tmp_path, "w");
    if (!f) return -1;

    char hex[HASH_HEX_SIZE + 1];
    for (int i = 0; i < g_index_buf.count; i++) {
        const IndexEntry *e = &g_index_buf.entries[i];
        hash_to_hex(&e->hash, hex);
        fprintf(f, "%o %s %llu %u %s\n",
                e->mode,
                hex,
                (unsigned long long)e->mtime_sec,
                (unsigned int)e->size,
                e->path);
    }

    fflush(f);
    fsync(fileno(f));
    fclose(f);

    if (rename(tmp_path, INDEX_FILE) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

// Stage a file: read its contents, write as a blob, update the index entry.
int index_add(Index *index, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open '%s'\n", path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < 0) { fclose(f); return -1; }

    // Heap-allocate file contents
    void *contents = malloc((size_t)file_size + 1);
    if (!contents) { fclose(f); return -1; }

    size_t nread = fread(contents, 1, (size_t)file_size, f);
    fclose(f);

    if (nread != (size_t)file_size) {
        free(contents);
        return -1;
    }

    // Write blob to object store
    ObjectID blob_id;
    if (object_write(OBJ_BLOB, contents, nread, &blob_id) != 0) {
        free(contents);
        return -1;
    }
    free(contents);

    // Get file metadata
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    uint32_t mode = (st.st_mode & S_IXUSR) ? 0100755 : 0100644;

    // Update existing entry or add a new one
    IndexEntry *existing = index_find(index, path);
    if (existing) {
        existing->mode      = mode;
        existing->hash      = blob_id;
        existing->mtime_sec = (uint64_t)st.st_mtime;
        existing->size      = (uint32_t)st.st_size;
    } else {
        if (index->count >= MAX_INDEX_ENTRIES) {
            fprintf(stderr, "error: index is full\n");
            return -1;
        }
        IndexEntry *e = &index->entries[index->count];
        e->mode      = mode;
        e->hash      = blob_id;
        e->mtime_sec = (uint64_t)st.st_mtime;
        e->size      = (uint32_t)st.st_size;
        strncpy(e->path, path, sizeof(e->path) - 1);
        e->path[sizeof(e->path) - 1] = '\0';
        index->count++;
    }

    return index_save(index);
}

// ─── tree_from_index ─────────────────────────────────────────────────────────
//
// Declared in tree.h, implemented here (not tree.c) so that the test_tree
// binary — which only links tree.o + object.o — does not get an undefined
// reference to index_load at link time.
//
// Recursively builds the tree hierarchy from sorted index entries.

// Static sorted buffer to avoid another 5.6MB stack allocation
static IndexEntry g_sorted_entries[MAX_INDEX_ENTRIES];

static int compare_index_by_path(const void *a, const void *b) {
    return strcmp(((const IndexEntry *)a)->path, ((const IndexEntry *)b)->path);
}

// Recursive helper: build one tree level for entries whose path starts with prefix.
static int write_tree_level(const IndexEntry *entries, int count,
                             const char *prefix, size_t prefix_len,
                             ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    int i = 0;
    while (i < count) {
        const char *path = entries[i].path;

        // Skip entries that don't belong to this prefix
        if (strncmp(path, prefix, prefix_len) != 0) {
            i++;
            continue;
        }

        const char *rel   = path + prefix_len;   // path relative to this level
        const char *slash = strchr(rel, '/');

        if (slash == NULL) {
            // Direct file — add as blob entry
            TreeEntry *te = &tree.entries[tree.count];
            te->mode = entries[i].mode;
            te->hash = entries[i].hash;
            size_t name_len = strlen(rel);
            if (name_len >= sizeof(te->name)) name_len = sizeof(te->name) - 1;
            memcpy(te->name, rel, name_len);
            te->name[name_len] = '\0';
            tree.count++;
            i++;
        } else {
            // Subdirectory — group all entries sharing this subdirectory name
            char subdir_name[256];
            size_t subdir_name_len = slash - rel;
            if (subdir_name_len >= sizeof(subdir_name))
                subdir_name_len = sizeof(subdir_name) - 1;
            memcpy(subdir_name, rel, subdir_name_len);
            subdir_name[subdir_name_len] = '\0';

            // Build new prefix for the subdirectory (e.g. "src/")
            char sub_prefix[512];
            snprintf(sub_prefix, sizeof(sub_prefix), "%s%s/", prefix, subdir_name);
            size_t sub_prefix_len = strlen(sub_prefix);

            // Recursively build the subtree
            ObjectID subtree_id;
            if (write_tree_level(entries, count,
                                  sub_prefix, sub_prefix_len, &subtree_id) != 0)
                return -1;

            // Add directory entry pointing to the subtree hash
            TreeEntry *te = &tree.entries[tree.count];
            te->mode = 0040000;
            te->hash = subtree_id;
            memcpy(te->name, subdir_name, subdir_name_len);
            te->name[subdir_name_len] = '\0';
            tree.count++;

            // Advance past all entries consumed by this subtree
            while (i < count &&
                   strncmp(entries[i].path, sub_prefix, sub_prefix_len) == 0)
                i++;
        }
    }

    // Serialize this tree level and write it to the object store
    void *data;
    size_t data_len;
    if (tree_serialize(&tree, &data, &data_len) != 0) return -1;
    int rc = object_write(OBJ_TREE, data, data_len, id_out);
    free(data);
    return rc;
}

int tree_from_index(ObjectID *id_out) {
    // Load the index into our static buffer to avoid stack overflow
    if (index_load(&g_index_buf) != 0) return -1;

    if (g_index_buf.count == 0) {
        // Empty index → write an empty tree object
        Tree empty;
        empty.count = 0;
        void *data;
        size_t data_len;
        if (tree_serialize(&empty, &data, &data_len) != 0) return -1;
        int rc = object_write(OBJ_TREE, data, data_len, id_out);
        free(data);
        return rc;
    }

    // Copy and sort entries by path (required for correct subdirectory grouping)
    memcpy(g_sorted_entries, g_index_buf.entries,
           g_index_buf.count * sizeof(IndexEntry));
    qsort(g_sorted_entries, g_index_buf.count,
          sizeof(IndexEntry), compare_index_by_path);

    return write_tree_level(g_sorted_entries, g_index_buf.count, "", 0, id_out);
}
