#ifndef ENCSQLITE_BUILD_INFO_H
#define ENCSQLITE_BUILD_INFO_H

#ifdef __cplusplus
extern "C" {
#endif

const char *encsqlite_build_sqlite_version(void);
int encsqlite_build_sqlite_version_number(void);
const char *encsqlite_build_sqlite_source_id(void);
const char *encsqlite_build_sqlite_import_method(void);

#ifdef __cplusplus
}
#endif

#endif
