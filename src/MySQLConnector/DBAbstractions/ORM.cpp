#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <map>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <thread>
#include <chrono>

#include "ORM.h"
#include "LightLinkedList.h"
#include "PriorityQueue.h"
#include "StringBuilder.h"
#include "AbstractPlatform.h"

extern char* trim(char *str);
extern int PROC_SHA256_MSG(unsigned char *msg, long msg_len, unsigned char *md, unsigned int md_len);
extern char* printBinStringToBuffer(unsigned char *str, int len, char *buffer);

using namespace std;


static std::map<uid_t, char*> uid_str_table;
static std::map<gid_t, char*> gid_str_table;

static PriorityQueue<LinkedList<ORMFileData*>*> _disk_thread_queues;
static PriorityQueue<ORMFileData*>              _databi_thread_queues;

const int THREAD_COUNT_DISK_MAX = 4; // How many disk threads should we allow?
const int THREAD_COUNT_DB_MAX   = 1; // How many disk threads should we allow?
const int MAX_QUERY_LENGTH      = 40000; //



/**
* Does longer-running disk access.
*/
void worker_thread_deep_disk(FSOCounts* stats, LinkedList<StringBuilder*>* logs) {
  while (1) {
    LinkedList<ORMFileData*>* wq = _disk_thread_queues.dequeue();
    if (wq) {
      ORMFileData* cur = wq->remove();
      while (cur) {
        cur->closelyExamine(stats, logs);
        cur = wq->remove();
      }
      delete wq;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}


/**
* No memory management is to be done by the thread. Only the main thread frees memory.
* Writes the def to the database.
*/
void worker_thread_db_write() {
  LibrarianDB* _db = LibrarianDB::getInstance();
  while (1) {
    ORMFileData* cur = _databi_thread_queues.dequeue();
    if (cur) {
      if (cur->dirty()) {
        LinkedList<ORMFileData*> objs_in_query;
        StringBuilder insert_query;
        cur->generateInsertQuery(&insert_query, nullptr);

        while ((nullptr != cur) && (insert_query.length() < MAX_QUERY_LENGTH)) {
          objs_in_query.insertAtHead(cur);
          if (objs_in_query.size() > 1) {
            insert_query.concat(",\n");
          }
          cur->generateInsertQuery(nullptr, &insert_query);
          //printf("insert_query size = %d       _databi_thread_queues size = %d        objs_in_query size = %d\n", insert_query.length(), _databi_thread_queues.size(), objs_in_query.size());
          cur = _databi_thread_queues.dequeue();
        }
        insert_query.concat(";");
        //printf("%s\n", insert_query.string());
        if (objs_in_query.size() > 0) {
          if (1 == _db->r_query(insert_query.string())) {
            while (objs_in_query.size() > 0) {
              cur = objs_in_query.remove();
              if (cur) {
                cur->markClean();
                //printf("DELETE from success case\n");
                delete cur;
              }
            }
          }
          else {
            c3p_log(LOG_ERR, __PRETTY_FUNCTION__, "Failed to save record to database.");
            printf("%s\n", (char*) insert_query.string());
          }
        }
      }
      else {
        //printf("DELETE from else case\n");
        delete cur;
      }
    }
    else {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
}



void ORMFileData::ship_db_thread(FSOCounts* stats, LinkedList<StringBuilder*>* logs) {
  new std::thread(worker_thread_db_write);
  new std::thread(worker_thread_deep_disk, stats, logs);
  new std::thread(worker_thread_deep_disk, stats, logs);
  new std::thread(worker_thread_deep_disk, stats, logs);
  new std::thread(worker_thread_deep_disk, stats, logs);
  new std::thread(worker_thread_deep_disk, stats, logs);
  new std::thread(worker_thread_deep_disk, stats, logs);
}


void FSOCounts::tally(ORMFileData* o) {
  if (o->isFile()) {
    files++;
  }
  else if (o->isDirectory()) {
    dirs++;
  }
  else if (o->isLink()) {
    links++;
  }
}


void FSOCounts::progressPrint() {
  //printf("\033[4ADirectories: %lu\n", dirs);
  //printf("Files:       %lu\n", files);
  //printf("Links:       %lu\n\n", links);
  //printf("_disk_thread_queues:       %d\n", _disk_thread_queues.size());
  //printf("_databi_thread_queues:     %d\n\n", _databi_thread_queues.size());
}



ORMFileData::ORMFileData(uint32_t dvid, char* p) : _dh_ver(dvid) {
  memset(_hash, 0, 32);
  memset(_mode, 0, sizeof(_mode));
  char* trimmed = trim(p);
  size_t path_len = strlen(trimmed);
  if (path_len) {
    _path = (char*) malloc(path_len+1);
    if (_path) {
      memcpy(_path, trimmed, path_len);
      *(_path + path_len) = '\0';
      _fill_from_stat();
    }
  }
}



ORMFileData::~ORMFileData() {
  if (_need_db_write) {
    //StringBuilder insert_query;
    //generateInsertQuery(&insert_query);
  }

  if (_path) {
    free(_path);
    _path = nullptr;
  }
}


int ORMFileData::closelyExamine(FSOCounts* stats, LinkedList<StringBuilder*>* logs) {
  if (!closelyExamined()) {
    if (isFile()) {
      _hash_file();
    }
    else if (isDirectory()) {
      dive(stats, logs);
    }
    else if (isLink()) {
      _closely_examined = true;
    }
    _need_db_write = true;
    _databi_thread_queues.insert(this);
    return 0;
  }
  return -1;
}


const int HASH_BUFFER_SIZE = 1024 * 1024;

/*
* Function takes a path and a buffer as arguments. The binary is hashed and the ASCII representation is
*   placed in the buffer. The number of bytes read is returned on success. 0 is returned on failure.
*/
int ORMFileData::_hash_file() {
  int return_value = -1;
  int fd = open(_path, O_RDONLY);
  if (fd >= 0) {
    uint8_t* self_mass   = (uint8_t*) alloca(HASH_BUFFER_SIZE);
    if (self_mass) {
      const EVP_MD *evp_md  = EVP_sha256();
      if (evp_md != NULL) {
        EVP_MD_CTX *cntxt = (EVP_MD_CTX *)(intptr_t) EVP_MD_CTX_create();
        EVP_DigestInit(cntxt, evp_md);
        ulong total_read = 0;
        do {
          int r_len = read(fd, self_mass, HASH_BUFFER_SIZE);
          if ((r_len > 0) || (0 == _fsize)) {
            EVP_DigestUpdate(cntxt, self_mass, r_len);
            total_read += r_len;
            //printf("%s is %lu bytes. %d\n", _path, total_read, r_len);
          }
          else {
            printf("Aborting read due to zero byte return. %s\n", _path);
            c3p_log(LOG_LEV_DEBUG, __PRETTY_FUNCTION__, "Aborting read due to zero byte return. %s\n", _path);
            total_read = _fsize;
          }
        } while (total_read < _fsize);
        uint md_len = 32;
        EVP_DigestFinal_ex(cntxt, _hash, &md_len);
        EVP_MD_CTX_destroy(cntxt);
        if (_fsize == total_read) {
          return_value = 0;
          _closely_examined = true;
        }
        else {
          c3p_log(LOG_ERR, __PRETTY_FUNCTION__, "Failed to run the hash on %s", _path);
        }
      }
      else {
        c3p_log(LOG_ERR, __PRETTY_FUNCTION__, "Failed to load the digest algo SHA256.");
      }
    }
    else {
      c3p_log(LOG_ERR, __PRETTY_FUNCTION__, "Failed to allocate %lu bytes from heap in pursuit of hashing %s", _fsize, _path);
    }
    close(fd);
  }
  else {
    c3p_log(LOG_ERR, __PRETTY_FUNCTION__, "Failed to open path for hashing: %s", _path);
  }
  return return_value;
}


/*
*
*/
int ORMFileData::_fill_from_stat() {
  struct stat64 statbuf;
  memset((void*) &statbuf, 0, sizeof(struct stat64));
  int return_value = lstat64((const char*) _path, &statbuf);
  if (0 == return_value) {
    _is_dir  = S_ISDIR(statbuf.st_mode);
    _is_file = S_ISREG(statbuf.st_mode);
    _is_link = S_ISLNK(statbuf.st_mode);
    if (_is_link || _is_file || _is_dir) {
      _uid = statbuf.st_uid;
      _gid = statbuf.st_gid;
      _mtime = statbuf.st_mtime;
      _ctime = statbuf.st_ctime;
      _exists = true;
      cache_uid_gid_strings();

      _mode[0] = (statbuf.st_mode & S_IRUSR) ? 'r' : '-';
      _mode[1] = (statbuf.st_mode & S_IWUSR) ? 'w' : '-';
      _mode[2] = (statbuf.st_mode & S_IXUSR) ? 'x' : '-';
      _mode[3] = (statbuf.st_mode & S_IRGRP) ? 'r' : '-';
      _mode[4] = (statbuf.st_mode & S_IWGRP) ? 'w' : '-';
      _mode[5] = (statbuf.st_mode & S_IXGRP) ? 'x' : '-';
      _mode[6] = (statbuf.st_mode & S_IROTH) ? 'r' : '-';
      _mode[7] = (statbuf.st_mode & S_IWOTH) ? 'w' : '-';
      _mode[8] = (statbuf.st_mode & S_IXOTH) ? 'x' : '-';

      if (_is_file) {
        _fsize = statbuf.st_size;
        //c3p_log(LOG_INFO, "Path is a file with size %lu: %s", _fsize, _path);
      }
      else if (_is_dir) {
        //c3p_log(LOG_INFO, "Path is a directory: %s", _path);
      }
      else {
        //c3p_log(LOG_INFO, "Path is a link: %s", _path);
      }
    }
    else {
      // TODO: Some unhandled filesystem object.
      c3p_log(LOG_WARNING, __PRETTY_FUNCTION__, "Unhandled filesystem object at path: %s", _path);
    }
  }
  else {
    perror("stat");
    c3p_log(LOG_ERR, __PRETTY_FUNCTION__, "Failed to lstat path: %s", _path);
  }

  return return_value;
}


/*
*
*/
long ORMFileData::dive(FSOCounts* fso_counts, LinkedList<StringBuilder*>* log) {
  DIR *dir;
  struct dirent *ent;
  int files  = 0;
  dir = opendir(_path);
  if (dir) {
    LinkedList<ORMFileData*>* fso_list = new LinkedList<ORMFileData*>();

    while ((ent = readdir(dir)) != nullptr) {
      if (strcasestr(ent->d_name, "..") && (strlen(ent->d_name) == 2)) {
        // Ignore .. entry
      }
      else if (strcasestr(ent->d_name, ".") && (strlen(ent->d_name) == 1)) {
        // Ignore . entry
      }
      else {
        StringBuilder temp_path(_path);
        temp_path.concatf("%s%s", ('/' == *(_path+strlen(_path)-1)) ? "" : "/", ent->d_name);
        ORMFileData* n_fd = new ORMFileData(_dh_ver, (char*) temp_path.string());
        if (n_fd) {
          fso_list->insertAtHead(n_fd);
          fso_counts->tally(n_fd);
        }
        else {
          c3p_log(LOG_ERR, __PRETTY_FUNCTION__, "Failed to allocate from heap for new ORMFileData.");
        }
      }
    }
    closedir(dir);
    _closely_examined = true;
    _disk_thread_queues.insert(fso_list);
    //fso_counts->progressPrint();
  }
  else{
    printf("Failed\n");
    c3p_log(LOG_ERR, __PRETTY_FUNCTION__, "Failed to open DIR %s", _path);
    return -1;
  }
  return files;
}


/*
* Write out the files into the database.
*
* Returns the number of files whose metadata was written.
*/
long ORMFileData::_write_files_to_database() {
  long return_value = 0;
  return return_value;
}


/*
*
*/
void ORMFileData::printDebug(StringBuilder* output) {
  if (_is_file) {
    output->concat("FILE ");
  }
  else if (_is_dir) {
    output->concat("DIR  ");
  }
  else if (_is_link) {
    output->concat("LINK ");
  }
  else {
    output->concat("???? ");
  }

  char h_buf[65];
  memset(h_buf, 0x00, 65);
  printBinStringToBuffer(_hash, 32, h_buf);
  output->concatf("%s ", h_buf);
  output->concatf("%9lu  ", _fsize);
  output->concatf("%s", _path);
}


/*
*
*/
void ORMFileData::generateInsertQuery(StringBuilder* output) {
  generateInsertQuery(output, output);
  output->concat(";");
}


/*
*
*/
void ORMFileData::generateInsertQuery(StringBuilder* baseline_string, StringBuilder* cycled_string) {
  if (baseline_string) {
    // If this was provided, we give the baseline insert string.
    baseline_string->concat("INSERT INTO `file_meta` (`id_dh_snapshot`, `ctime`, `mtime`, `size`, `userflags`, `isdir`, `isfile`, `islink`, `examined`, `rel_path`, `sha256`, `owner`, `group`, `perms`) VALUES ");
  }
  if (cycled_string) {
    // If this was provided, we give the string specific for this instance.
    char h_buf[65];
    memset(h_buf, 0, 65);
    struct tm timeinfo;

    cycled_string->concatf("('%d',", _dh_ver);    // id_dh_snapshot

    localtime_r(&_ctime, &timeinfo);
    strftime(h_buf, sizeof(h_buf), "%Y-%m-%d %H:%M:%S", &timeinfo);
    cycled_string->concatf("'%s',", h_buf);
    memset(h_buf, 0, 65);

    localtime_r(&_mtime, &timeinfo);
    strftime(h_buf, sizeof(h_buf), "%Y-%m-%d %H:%M:%S", &timeinfo);
    cycled_string->concatf("'%s',", h_buf);
    memset(h_buf, 0, 65);

    cycled_string->concatf("'%lu','%d','%d','%d','%d','%d','", _fsize, 0, _is_dir?1:0, _is_file?1:0, _is_link?1:0, _closely_examined?1:0);

    LibrarianDB* db = LibrarianDB::getInstance();
    db->escape_string(_path, cycled_string);

    printBinStringToBuffer(_hash, 32, h_buf);
    cycled_string->concatf("','%s','%s','%s','%s')", h_buf, uid_str_table[_uid], gid_str_table[_gid], _mode);
  }
}


/*
*
*/
void ORMFileData::cache_uid_gid_strings() {
  if (!gid_str_table[_gid]) {
    struct group* grp_s  = getgrgid(_gid);
    if (grp_s) {
      gid_str_table[_gid] = grp_s->gr_name;
      c3p_log(LOG_INFO, __PRETTY_FUNCTION__, "Added group %s", grp_s->gr_name);
    }
  }
  if (!uid_str_table[_uid]) {
    struct passwd* psw_s = getpwuid(_uid);
    if (psw_s) {
      uid_str_table[_uid] = psw_s->pw_name;
      c3p_log(LOG_INFO, __PRETTY_FUNCTION__, "Added user %s", psw_s->pw_name);
    }
  }
}
