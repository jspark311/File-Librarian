#include "MySQLConnector/MySQLConnector.h"
#include "DataStructures/LightLinkedList.h"
#include "DataStructures/PriorityQueue.h"
#include "DataStructures/StringBuilder.h"


#ifndef __ORM_CLASS_H__
#define __ORM_CLASS_H__


class ORMFileData;

/*
* A class that represents things that need to be done.
*/
class WorkItem {
};


/*
*
*/
class FSOCounts {
  public:
    FSOCounts() {};
    ~FSOCounts() {};

    void tally(ORMFileData* o);
    void progressPrint();


    unsigned long dirs  = 0;
    unsigned long files = 0;
    unsigned long links = 0;


  private:
};


class LibrarianDB : public MySQLConnector {
  public:
    LibrarianDB();
    ~LibrarianDB();

    static LibrarianDB* getInstance();


  private:
    uint32_t _database_version = 0;
    LinkedList<WorkItem*> work_items;
};



/*
*
*/
class ORM {
  public:
    virtual void generateInsertQuery(StringBuilder*) = 0;
    virtual void generateInsertQuery(StringBuilder*, StringBuilder*) = 0;


  protected:

  private:
};



/*
*
*/
class ORMDatahiveVersion : public ORM {
  public:
    ORMDatahiveVersion(uint32_t, char*);
    virtual ~ORMDatahiveVersion();

    void generateInsertQuery(StringBuilder*);
    void generateInsertQuery(StringBuilder*, StringBuilder*);

    inline int countDirectories() {   return _fso_totals.dirs;     };
    inline int countFiles() {         return _fso_totals.files;    };
    inline int countLinks() {         return _fso_totals.links;    };
    inline bool dirty() {             return !(_saved_to_db);      };
    inline bool scanComplete() {      return _scan_complete;       };
    inline void markClean() {         _saved_to_db = true;    };

    int scan();
    long commit();
    void setTag(StringBuilder*);
    void setNotes(StringBuilder*);
    void printDebug(StringBuilder*);


  private:
    const uint32_t _dh_ver;
    char*          _tag       = nullptr;
    char*          _path      = nullptr;
    char*          _notes     = nullptr;
    LibrarianDB*   _db        = nullptr;
    ORMFileData*   _root_obj  = nullptr;
    LinkedList<StringBuilder*> _logs;
    time_t _catalog_start_time = 0;
    time_t _catalog_stop_time  = 0;
    time_t _copy_start_time    = 0;
    time_t _copy_stop_time     = 0;
    time_t _scan_duration      = 0;
    time_t _copy_duration      = 0;
    FSOCounts _fso_totals;

    bool    _saved_to_db    = false;
    bool    _scan_complete  = false;
    bool    _copy_complete  = false;

    void _mark_scan_started();
    void _mark_scan_complete();
    void _mark_copy_started();
    void _mark_copy_complete();
};


/*
*
*/
class ORMFileData : public ORM {
  public:
    ORMFileData(uint32_t, char*);
    virtual ~ORMFileData();

    void generateInsertQuery(StringBuilder*);
    void generateInsertQuery(StringBuilder*, StringBuilder*);

    inline bool exists() {        return _exists;            };
    inline bool isDirectory() {   return _is_dir;            };
    inline bool isFile() {        return _is_file;           };
    inline bool isLink() {        return _is_link;           };
    inline bool dirty() {         return _need_db_write;     };
    inline void markClean() {     _need_db_write = false;    };

    inline bool closelyExamined() {  return _closely_examined;  };

    int closelyExamine(FSOCounts*, LinkedList<StringBuilder*>*);
    void printDebug(StringBuilder*);

    static void ship_db_thread(FSOCounts*, LinkedList<StringBuilder*>*);


  private:
    const uint32_t _dh_ver;
    uint8_t _hash[32];
    char    _mode[12];
    char*   _path    = nullptr;
    ulong   _fsize   = 0;
    uid_t   _uid     = 0;
    gid_t   _gid     = 0;
    time_t  _ctime;
    time_t  _mtime;
    bool    _exists  = false;
    bool    _is_dir  = false;
    bool    _is_file = false;
    bool    _is_link = false;
    bool    _closely_examined = false;
    bool    _need_db_write    = false;


    int _hash_file();
    long dive(FSOCounts*, LinkedList<StringBuilder*>*);
    int _fill_from_stat();
    void cache_uid_gid_strings();
    long _write_files_to_database();
};


#endif
