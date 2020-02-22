#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <syslog.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>

#include "ORM.h"
#include "DataStructures/LightLinkedList.h"
#include "DataStructures/PriorityQueue.h"
#include "DataStructures/StringBuilder.h"

extern char* trim(char *str);
extern char* printBinStringToBuffer(unsigned char *str, int len, char *buffer);
extern void fp_log(const char *fxn_name, int severity, const char *message, ...);

using namespace std;



ORMDatahiveVersion::ORMDatahiveVersion(char* p) {
  _db = LibrarianDB::getInstance();
  char* trimmed = trim(p);
  size_t path_len = strlen(trimmed);
  if (path_len) {
    // TODO: We pool any quantities we can know at this point.
    _path = (char*) malloc(path_len+1);
    if (_path) {
      memcpy(_path, trimmed, path_len);
      *(_path + path_len) = '\0';
    }
  }
}


ORMDatahiveVersion::ORMDatahiveVersion(uint32_t dv, char* p) : _dh_ver(dv) {
  _db = LibrarianDB::getInstance();
  char* trimmed = trim(p);
  size_t path_len = strlen(trimmed);
  if (path_len) {
    // TODO: We pool any quantities we can know at this point.
    _path = (char*) malloc(path_len+1);
    if (_path) {
      memcpy(_path, trimmed, path_len);
      *(_path + path_len) = '\0';
    }
  }
}



ORMDatahiveVersion::~ORMDatahiveVersion() {
  while (_logs.size() > 0) {
    delete _logs.remove();
  }

  if (_root_obj) {
    delete _root_obj;
    _root_obj = nullptr;
  }
  if (_path) {
    free(_path);
    _path = nullptr;
  }
  if (_notes) {
    free(_notes);
    _notes = nullptr;
  }
  if (_tag) {
    free(_tag);
    _tag = nullptr;
  }
}


void ORMDatahiveVersion::_mark_scan_started() {
  time(&_catalog_start_time);
  _scan_complete = false;
}

void ORMDatahiveVersion::_mark_scan_complete() {
  time(&_catalog_stop_time);
  _scan_duration = _catalog_stop_time - _catalog_start_time;
  _scan_complete = true;
}

void ORMDatahiveVersion::_mark_copy_started() {
  time(&_copy_start_time);
  _scan_complete = false;
}

void ORMDatahiveVersion::_mark_copy_complete() {
  time(&_copy_stop_time);
  _copy_duration = _copy_stop_time - _copy_start_time;
  _copy_complete = true;
}



void ORMDatahiveVersion::printDebug(StringBuilder* output) {
  char buf0[65];
  struct tm timeinfo;
  output->concatf("DataHive catalog version %lu\n", _dh_ver);
  if (_tag) {
    output->concatf("  Tag:   %s\n", _tag);
  }
  output->concatf("  Path:  %s\n", _path);
  if (_notes) {
    output->concatf("  Notes: %s\n", _notes);
  }

  if (0 != _catalog_start_time) {
    memset(buf0, 0, 65);
    localtime_r(&_catalog_start_time, &timeinfo);
    strftime(buf0, sizeof(buf0), "%Y-%m-%d %H:%M:%S", &timeinfo);
    output->concatf("  Scan started at %s", buf0);
    if (_scan_complete) {
      char buf1[65];
      memset(buf1, 0, 65);
      localtime_r(&_scan_duration, &timeinfo);
      strftime(buf1, sizeof(buf1), "%H:%M:%S", &timeinfo);
      output->concatf(" and took %s\n", buf1);
    }
    else {
      output->concat("\n");
    }
    output->concatf("    Directories: %d\n", countDirectories());
    output->concatf("    Files:       %d\n", countFiles());
    output->concatf("    Links:       %d\n", countLinks());
  }
  if (0 != _copy_start_time) {
    memset(buf0, 0, 65);
    localtime_r(&_copy_start_time, &timeinfo);
    strftime(buf0, sizeof(buf0), "%Y-%m-%d %H:%M:%S", &timeinfo);
    output->concatf("  Copy started at %s", buf0);
    if (_copy_complete) {
      char buf1[65];
      memset(buf1, 0, 65);
      localtime_r(&_copy_duration, &timeinfo);
      strftime(buf1, sizeof(buf1), "%H:%M:%S", &timeinfo);
      output->concatf(" and took %s\n", buf1);
    }
    else {
      output->concat("\n");
    }
  }

}


/*
*
*/
void ORMDatahiveVersion::generateInsertQuery(StringBuilder* output) {
  generateInsertQuery(output, output);
  output->concat(";");
}


/*
*
*/
void ORMDatahiveVersion::generateInsertQuery(StringBuilder* baseline_string, StringBuilder* cycled_string) {
  LibrarianDB* db = LibrarianDB::getInstance();
  if (baseline_string) {
    // If this was provided, we give the baseline insert string.
    baseline_string->concat("INSERT INTO `datahive_version` (`tag`, `count_files`, `count_links`, `count_directories`, `rel_path`, `notes`) VALUES ");
  }
  if (cycled_string) {
    cycled_string->concat("('");
    db->escape_string((_tag) ? _tag : ((char*) "The-Tagless"), cycled_string);
    cycled_string->concatf("','%d','%d','%d','", _fso_totals.files, _fso_totals.links, _fso_totals.dirs);
    db->escape_string(_path, cycled_string);
    cycled_string->concat("','");
    db->escape_string((_notes) ? _notes : ((char*) "No notes"), cycled_string);
    cycled_string->concat("')");
  }
}


/*
*
*/
int ORMDatahiveVersion::scan() {
  int ret    = -1;
  _mark_scan_started();
  ORMFileData::ship_db_thread(&_fso_totals, &_logs);
  printf("Scan started for path %s\n\n\n\n\n", _path);

  _root_obj = new ORMFileData(_dh_ver, _path);
  if (_root_obj) {
    _fso_totals.tally(_root_obj);  // Including the root.
    _root_obj->closelyExamine(&_fso_totals, &_logs);
    _mark_scan_complete();
    ret = 0;
  }
  else {
    fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to scan.");
  }
  return ret;
}


/*
*
*/
long ORMDatahiveVersion::commit() {
  long files = 0;

  if (dirty()) {
    StringBuilder insert_query;
    generateInsertQuery(&insert_query);
    if (1 == _db->r_query(insert_query.string())) {
      _dh_ver = _db->last_insert_id();
      _saved_to_db = true;
    }
    else {
      fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to save ORMDatahiveVersion to database.");
    }
  }
  return files;
}


/*
*
*/
void ORMDatahiveVersion::setTag(StringBuilder* n_raw) {
  if (_tag) {
    // If there is already a tag present, remove it.
    free(_tag);
    _tag = nullptr;
  }
  n_raw->string();
  char* trimmed = n_raw->position_trimmed(0);
  int len = strlen(trimmed);
  if (len > 0) {
    _tag = (char*) malloc(len+1);
    if (_tag) {
      memcpy(_tag, n_raw->string(), len);
      *(_tag + len) = '\0';
    }
  }
}


/*
*
*/
void ORMDatahiveVersion::setNotes(StringBuilder* n_raw) {
  if (_notes) {
    // If there are already notes present, remove them.
    free(_notes);
    _notes = nullptr;
  }
  n_raw->string();
  char* trimmed = n_raw->position_trimmed(0);
  int len = strlen(trimmed);
  if (len > 0) {
    _notes = (char*) malloc(len+1);
    if (_notes) {
      memcpy(_notes, trimmed, len);
      *(_notes + len) = '\0';
    }
  }
}
