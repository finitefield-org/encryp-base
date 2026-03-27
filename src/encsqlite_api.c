#include "encsqlite/api.h"

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef enum {
  COPY_SWAP_PHASE_UNKNOWN = 0,
  COPY_SWAP_PHASE_PREPARED,
  COPY_SWAP_PHASE_BACKED_UP,
  COPY_SWAP_PHASE_REPLACED
} copy_swap_phase;

static const char k_copy_swap_marker_suffix[] = ".encsqlite.recovery";
static const char k_copy_swap_backup_suffix[] = ".encsqlite.bak";
static const char k_copy_swap_temp_suffix[] = ".encsqlite-";

static int path_append_suffix(
    const char *path,
    const char *suffix,
    char **out_path) {
  size_t path_len;
  size_t suffix_len;
  char *result;

  if (path == NULL || suffix == NULL || out_path == NULL) {
    return SQLITE_MISUSE;
  }

  path_len = strlen(path);
  suffix_len = strlen(suffix);
  result = (char *)malloc(path_len + suffix_len + 1);
  if (result == NULL) {
    return SQLITE_NOMEM;
  }

  memcpy(result, path, path_len);
  memcpy(result + path_len, suffix, suffix_len + 1);
  *out_path = result;
  return SQLITE_OK;
}

static int split_path_components(
    const char *path,
    char **out_dir,
    char **out_base) {
  const char *slash;
  size_t dir_len;
  char *dir;
  char *base;

  if (path == NULL || out_dir == NULL || out_base == NULL) {
    return SQLITE_MISUSE;
  }

  slash = strrchr(path, '/');
  if (slash == NULL) {
    dir = strdup(".");
    base = strdup(path);
  } else if (slash == path) {
    dir = strdup("/");
    base = strdup(slash + 1);
  } else {
    dir_len = (size_t)(slash - path);
    dir = (char *)malloc(dir_len + 1);
    base = strdup(slash + 1);
    if (dir != NULL) {
      memcpy(dir, path, dir_len);
      dir[dir_len] = '\0';
    }
  }

  if (dir == NULL || base == NULL) {
    free(dir);
    free(base);
    return SQLITE_NOMEM;
  }

  *out_dir = dir;
  *out_base = base;
  return SQLITE_OK;
}

static char *join_dir_entry(const char *dir, const char *entry_name) {
  size_t dir_len;
  size_t entry_len;
  char *result;

  if (dir == NULL || entry_name == NULL) {
    return NULL;
  }

  dir_len = strlen(dir);
  entry_len = strlen(entry_name);
  result = (char *)malloc(dir_len + 1 + entry_len + 1);
  if (result == NULL) {
    return NULL;
  }

  memcpy(result, dir, dir_len);
  result[dir_len] = '/';
  memcpy(result + dir_len + 1, entry_name, entry_len + 1);
  return result;
}

static int remove_temp_files_for_destination(const char *destination_path) {
  char *dir = NULL;
  char *base = NULL;
  char *prefix = NULL;
  DIR *directory = NULL;
  struct dirent *entry;
  size_t prefix_len;
  int rc = SQLITE_OK;

  rc = split_path_components(destination_path, &dir, &base);
  if (rc != SQLITE_OK) {
    return rc;
  }

  prefix_len = strlen(base) + strlen(k_copy_swap_temp_suffix);
  prefix = (char *)malloc(prefix_len + 1);
  if (prefix == NULL) {
    free(dir);
    free(base);
    return SQLITE_NOMEM;
  }
  snprintf(prefix, prefix_len + 1, "%s%s", base, k_copy_swap_temp_suffix);

  directory = opendir(dir);
  if (directory == NULL) {
    free(prefix);
    free(dir);
    free(base);
    return SQLITE_OK;
  }

  while ((entry = readdir(directory)) != NULL) {
    char *full_path;

    if (strncmp(entry->d_name, prefix, prefix_len) != 0) {
      continue;
    }
    full_path = join_dir_entry(dir, entry->d_name);
    if (full_path == NULL) {
      rc = SQLITE_NOMEM;
      break;
    }
    if (unlink(full_path) != 0 && errno != ENOENT) {
      rc = SQLITE_IOERR;
    }
    free(full_path);
  }

  closedir(directory);
  free(prefix);
  free(dir);
  free(base);
  return rc;
}

static int write_recovery_phase(const char *destination_path, copy_swap_phase phase) {
  char *marker_path = NULL;
  FILE *file = NULL;
  int rc;

  rc = path_append_suffix(destination_path, k_copy_swap_marker_suffix, &marker_path);
  if (rc != SQLITE_OK) {
    return rc;
  }

  file = fopen(marker_path, "wb");
  if (file == NULL) {
    free(marker_path);
    return SQLITE_CANTOPEN;
  }

  if (fprintf(file, "phase=%d\n", (int)phase) < 0 || fflush(file) != 0 || fsync(fileno(file)) != 0) {
    rc = SQLITE_IOERR_FSYNC;
  } else {
    rc = SQLITE_OK;
  }

  if (fclose(file) != 0 && rc == SQLITE_OK) {
    rc = SQLITE_IOERR;
  }
  free(marker_path);
  return rc;
}

static int read_recovery_phase(const char *destination_path, copy_swap_phase *out_phase) {
  char *marker_path = NULL;
  FILE *file = NULL;
  char line[64];
  copy_swap_phase phase = COPY_SWAP_PHASE_UNKNOWN;
  int rc;

  if (out_phase == NULL) {
    return SQLITE_MISUSE;
  }
  *out_phase = COPY_SWAP_PHASE_UNKNOWN;

  rc = path_append_suffix(destination_path, k_copy_swap_marker_suffix, &marker_path);
  if (rc != SQLITE_OK) {
    return rc;
  }

  if (access(marker_path, F_OK) != 0) {
    free(marker_path);
    return SQLITE_OK;
  }

  file = fopen(marker_path, "rb");
  if (file == NULL) {
    free(marker_path);
    *out_phase = COPY_SWAP_PHASE_PREPARED;
    return SQLITE_OK;
  }

  while (fgets(line, sizeof(line), file) != NULL) {
    if (strncmp(line, "phase=", 6) == 0) {
      int value = atoi(line + 6);
      if (value >= COPY_SWAP_PHASE_PREPARED && value <= COPY_SWAP_PHASE_REPLACED) {
        phase = (copy_swap_phase)value;
      }
      break;
    }
  }

  fclose(file);
  free(marker_path);
  if (phase == COPY_SWAP_PHASE_UNKNOWN) {
    phase = COPY_SWAP_PHASE_PREPARED;
  }
  *out_phase = phase;
  return SQLITE_OK;
}

static int recover_copy_swap_artifacts(const char *destination_path) {
  char *marker_path = NULL;
  char *backup_path = NULL;
  copy_swap_phase phase = COPY_SWAP_PHASE_UNKNOWN;
  int rc;

  if (destination_path == NULL) {
    return SQLITE_MISUSE;
  }

  rc = path_append_suffix(destination_path, k_copy_swap_marker_suffix, &marker_path);
  if (rc != SQLITE_OK) {
    return rc;
  }
  rc = path_append_suffix(destination_path, k_copy_swap_backup_suffix, &backup_path);
  if (rc != SQLITE_OK) {
    free(marker_path);
    return rc;
  }

  if (access(marker_path, F_OK) != 0) {
    (void)remove_temp_files_for_destination(destination_path);
    unlink(backup_path);
    free(marker_path);
    free(backup_path);
    return SQLITE_OK;
  }

  rc = read_recovery_phase(destination_path, &phase);
  if (rc != SQLITE_OK) {
    free(marker_path);
    free(backup_path);
    return rc;
  }

  (void)remove_temp_files_for_destination(destination_path);

  switch (phase) {
    case COPY_SWAP_PHASE_PREPARED:
      unlink(backup_path);
      unlink(marker_path);
      break;
    case COPY_SWAP_PHASE_BACKED_UP:
      if (access(backup_path, F_OK) == 0) {
        if (access(destination_path, F_OK) != 0) {
          if (rename(backup_path, destination_path) != 0 && errno != ENOENT) {
            rc = SQLITE_IOERR;
          }
        } else {
          unlink(backup_path);
        }
      }
      unlink(marker_path);
      break;
    case COPY_SWAP_PHASE_REPLACED:
    case COPY_SWAP_PHASE_UNKNOWN:
    default:
      unlink(backup_path);
      unlink(marker_path);
      break;
  }

  free(marker_path);
  free(backup_path);
  return rc;
}

static int normalize_copy_options(
    encsqlite_open_options *out_options,
    const encsqlite_open_options *base_options,
    int read_only,
    int create_if_missing,
    int journal_mode_wal) {
  if (out_options == NULL) {
    return SQLITE_MISUSE;
  }

  memset(out_options, 0, sizeof(*out_options));
  out_options->read_only = read_only;
  out_options->create_if_missing = create_if_missing;
  out_options->expect_application_id = base_options != NULL ? base_options->expect_application_id : 0;
  out_options->application_id = base_options != NULL ? base_options->application_id : 0U;
  out_options->journal_mode_wal = journal_mode_wal;
  return SQLITE_OK;
}

static int make_temp_path_with_suffix(
    const char *base_path,
    const char *suffix,
    char **out_temp_path) {
  size_t destination_len;
  size_t temp_len;
  char *temp_path;
  int fd;

  if (base_path == NULL || suffix == NULL || out_temp_path == NULL) {
    return SQLITE_MISUSE;
  }

  destination_len = strlen(base_path);
  temp_len = destination_len + strlen(suffix) + 1;
  temp_path = (char *)malloc(temp_len);
  if (temp_path == NULL) {
    return SQLITE_NOMEM;
  }

  if (snprintf(temp_path, temp_len, "%s%s", base_path, suffix) < 0) {
    free(temp_path);
    return SQLITE_ERROR;
  }

  fd = mkstemp(temp_path);
  if (fd < 0) {
    free(temp_path);
    return SQLITE_CANTOPEN;
  }
  close(fd);

  *out_temp_path = temp_path;
  return SQLITE_OK;
}

static int make_temp_path(const char *destination_path, char **out_temp_path) {
  return make_temp_path_with_suffix(destination_path, ".encsqlite-XXXXXX", out_temp_path);
}

static int sync_file_path(const char *path) {
  int fd;
  int rc = SQLITE_OK;

  if (path == NULL) {
    return SQLITE_MISUSE;
  }

  fd = open(path, O_RDONLY);
  if (fd < 0) {
    return SQLITE_CANTOPEN;
  }
  if (fsync(fd) != 0) {
    rc = SQLITE_IOERR_FSYNC;
  }
  close(fd);
  return rc;
}

static int sync_parent_directory(const char *path) {
  char *directory_path = NULL;
  DIR *dir = NULL;
  int rc = SQLITE_OK;
  char *slash;

  if (path == NULL) {
    return SQLITE_MISUSE;
  }

  directory_path = strdup(path);
  if (directory_path == NULL) {
    return SQLITE_NOMEM;
  }

  slash = strrchr(directory_path, '/');
  if (slash == NULL) {
    strcpy(directory_path, ".");
  } else if (slash == directory_path) {
    slash[1] = '\0';
  } else {
    *slash = '\0';
  }

  dir = opendir(directory_path);
  if (dir == NULL) {
    free(directory_path);
    return SQLITE_CANTOPEN;
  }

  if (fsync(dirfd(dir)) != 0) {
    rc = SQLITE_IOERR_FSYNC;
  }

  closedir(dir);
  free(directory_path);
  return rc;
}

static int run_quick_check(sqlite3 *db) {
  sqlite3_stmt *stmt = NULL;
  int rc;
  int saw_row = 0;

  if (db == NULL) {
    return SQLITE_MISUSE;
  }

  rc = sqlite3_prepare_v2(db, "PRAGMA quick_check(1);", -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    return rc;
  }

  while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    const unsigned char *text = sqlite3_column_text(stmt, 0);
    saw_row = 1;
    if (text == NULL || strcmp((const char *)text, "ok") != 0) {
      rc = SQLITE_CORRUPT;
      break;
    }
  }

  if (rc == SQLITE_DONE && !saw_row) {
    rc = SQLITE_ERROR;
  } else if (rc == SQLITE_DONE) {
    rc = SQLITE_OK;
  }

  sqlite3_finalize(stmt);
  return rc;
}

static int run_backup(sqlite3 *dest_db, sqlite3 *source_db) {
  sqlite3_backup *backup = NULL;
  int rc;

  if (dest_db == NULL || source_db == NULL) {
    return SQLITE_MISUSE;
  }

  backup = sqlite3_backup_init(dest_db, "main", source_db, "main");
  if (backup == NULL) {
    return sqlite3_errcode(dest_db);
  }

  while (1) {
    rc = sqlite3_backup_step(backup, 32);
    if (rc == SQLITE_OK || rc == SQLITE_BUSY || rc == SQLITE_LOCKED) {
      if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED) {
        sqlite3_sleep(10);
      }
      continue;
    }
    break;
  }

  if (rc == SQLITE_DONE) {
    rc = SQLITE_OK;
  }

  if (sqlite3_backup_finish(backup) != SQLITE_OK && rc == SQLITE_OK) {
    rc = sqlite3_errcode(dest_db);
  }

  return rc;
}

static int open_connection_for_copy(
    encsqlite_connection **out_connection,
    const char *path,
    const encsqlite_key_material *key_material,
    const encsqlite_open_options *base_options,
    int read_only,
    int create_if_missing,
    int journal_mode_wal) {
  encsqlite_open_options options;
  int rc;

  rc = normalize_copy_options(&options, base_options, read_only, create_if_missing, journal_mode_wal);
  if (rc != SQLITE_OK) {
    return rc;
  }

  return encsqlite_open_v2(out_connection, path, key_material, &options);
}

static int create_normalized_plain_stage(
    const char *source_path,
    const char *destination_path,
    const encsqlite_key_material *source_key,
    const encsqlite_open_options *options,
    char **out_stage_path) {
  encsqlite_connection *source_connection = NULL;
  encsqlite_connection *stage_connection = NULL;
  sqlite3 *source_db = NULL;
  sqlite3 *stage_db = NULL;
  char *stage_path = NULL;
  int rc;

  if (source_path == NULL || destination_path == NULL || out_stage_path == NULL) {
    return SQLITE_MISUSE;
  }
  *out_stage_path = NULL;

  rc = make_temp_path_with_suffix(destination_path, ".stage-XXXXXX", &stage_path);
  if (rc != SQLITE_OK) {
    return rc;
  }

  rc = open_connection_for_copy(
      &source_connection,
      source_path,
      source_key,
      options,
      1,
      0,
      0);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }
  source_db = encsqlite_connection_sqlite3(source_connection);

  rc = open_connection_for_copy(
      &stage_connection,
      stage_path,
      NULL,
      options,
      0,
      1,
      0);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }
  stage_db = encsqlite_connection_sqlite3(stage_connection);
  sqlite3_set_authorizer(stage_db, NULL, NULL);

  rc = run_backup(stage_db, source_db);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  {
    int reserve_bytes = ENCSQLITE_PAGE_RESERVED_BYTES;
    (void)sqlite3_file_control(stage_db, NULL, SQLITE_FCNTL_RESERVE_BYTES, &reserve_bytes);
  }

  rc = sqlite3_exec(stage_db, "VACUUM;", NULL, NULL, NULL);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  rc = run_quick_check(stage_db);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  rc = encsqlite_close_secure(stage_connection);
  stage_connection = NULL;
  stage_db = NULL;
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  rc = sync_file_path(stage_path);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  *out_stage_path = stage_path;
  stage_path = NULL;
  rc = SQLITE_OK;

cleanup:
  if (stage_connection != NULL) {
    (void)encsqlite_close_secure(stage_connection);
  }
  if (source_connection != NULL) {
    (void)encsqlite_close_secure(source_connection);
  }
  if (stage_path != NULL) {
    unlink(stage_path);
    free(stage_path);
  }
  return rc;
}

static int copy_swap_database(
    const char *source_path,
    const char *destination_path,
    const encsqlite_key_material *source_key,
    const encsqlite_key_material *destination_key,
    const encsqlite_open_options *options) {
  encsqlite_connection *source_connection = NULL;
  encsqlite_connection *destination_connection = NULL;
  sqlite3 *source_db = NULL;
  sqlite3 *destination_db = NULL;
  char *temp_path = NULL;
  char *backup_path = NULL;
  char *marker_path = NULL;
  int backup_created = 0;
  int rc;

  if (source_path == NULL || destination_path == NULL || destination_key == NULL) {
    return SQLITE_MISUSE;
  }

  rc = recover_copy_swap_artifacts(destination_path);
  if (rc != SQLITE_OK) {
    return rc;
  }

  rc = path_append_suffix(destination_path, k_copy_swap_backup_suffix, &backup_path);
  if (rc != SQLITE_OK) {
    return rc;
  }

  rc = path_append_suffix(destination_path, k_copy_swap_marker_suffix, &marker_path);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  rc = make_temp_path(destination_path, &temp_path);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  rc = open_connection_for_copy(
      &source_connection,
      source_path,
      source_key,
      options,
      1,
      0,
      0);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }
  source_db = encsqlite_connection_sqlite3(source_connection);

  rc = open_connection_for_copy(
      &destination_connection,
      temp_path,
      destination_key,
      options,
      0,
      1,
      0);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }
  destination_db = encsqlite_connection_sqlite3(destination_connection);

  rc = write_recovery_phase(destination_path, COPY_SWAP_PHASE_PREPARED);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  rc = run_backup(destination_db, source_db);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  rc = run_quick_check(destination_db);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  rc = encsqlite_close_secure(destination_connection);
  destination_connection = NULL;
  destination_db = NULL;
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  rc = sync_file_path(temp_path);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  rc = write_recovery_phase(destination_path, COPY_SWAP_PHASE_BACKED_UP);
  if (rc != SQLITE_OK) {
    goto cleanup;
  }

  if (access(destination_path, F_OK) == 0) {
    if (rename(destination_path, backup_path) != 0) {
      if (errno != ENOENT) {
        rc = SQLITE_IOERR;
        goto cleanup;
      }
    } else {
      backup_created = 1;
      rc = sync_parent_directory(destination_path);
      if (rc != SQLITE_OK) {
        goto cleanup;
      }
    }
  }

  if (rename(temp_path, destination_path) != 0) {
    rc = SQLITE_IOERR;
    goto cleanup;
  }

  rc = sync_parent_directory(destination_path);

cleanup:
  if (rc == SQLITE_OK || !backup_created) {
    if (marker_path != NULL) {
      unlink(marker_path);
    }
    if (backup_path != NULL) {
      unlink(backup_path);
    }
  }
  if (destination_connection != NULL) {
    (void)encsqlite_close_secure(destination_connection);
  }
  if (source_connection != NULL) {
    (void)encsqlite_close_secure(source_connection);
  }
  if (temp_path != NULL) {
    unlink(temp_path);
    free(temp_path);
  }
  free(marker_path);
  free(backup_path);
  return rc;
}

int encsqlite_migrate_plaintext(
    const char *source_path,
    const char *destination_path,
    const encsqlite_key_material *destination_key,
    const encsqlite_open_options *options) {
  char *stage_path = NULL;
  int rc;

  rc = create_normalized_plain_stage(
      source_path,
      destination_path,
      NULL,
      options,
      &stage_path);
  if (rc != SQLITE_OK) {
    return rc;
  }

  rc = copy_swap_database(
      stage_path,
      destination_path,
      NULL,
      destination_key,
      options);
  unlink(stage_path);
  free(stage_path);
  return rc;
}

int encsqlite_rekey_copy_swap(
    const char *source_path,
    const char *destination_path,
    const encsqlite_key_material *source_key,
    const encsqlite_key_material *destination_key,
    const encsqlite_open_options *options) {
  return copy_swap_database(
      source_path,
      destination_path,
      source_key,
      destination_key,
      options);
}

int encsqlite_export(
    const char *source_path,
    const char *destination_path,
    const encsqlite_key_material *key_material,
    const encsqlite_open_options *options) {
  return copy_swap_database(
      source_path,
      destination_path,
      key_material,
      key_material,
      options);
}
