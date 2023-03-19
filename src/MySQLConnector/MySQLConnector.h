#include <mysql/mysql.h>
#include "StringBuilder.h"
#include "Image/GfxUI.h"

#ifndef MYSQL_CONNECTOR_H
#define MYSQL_CONNECTOR_H 1

// This is the default path to the DB we are likely to use.
#define   DEFAULT_CONF_FILE   "db.conf"

typedef uint8_t LogLevel;
class GfxUIMySQL;

class MySQLConnector {
  friend class GfxUIMySQL;

    public:
        MySQLConnector(void);
        ~MySQLConnector(void);

        char *node_id;

        MYSQL       *mysql;
        MYSQL_RES   *result;
        int         db_connected;           // 0 if not. 1 if so. -1 if error.
        bool        no_free_on_destructor;  // This is meant to prevent child processes from freeing the DB when their threads terminate.

        int provisionConnectionDetails(char *filename);
        int dbConnected(void);
        void print_db_conn_detail(void);
        int r_query(char *query);
        int r_query(unsigned char *query);
        int r_query(const char *query);
        long escape_string(char*, StringBuilder*);

        int last_insert_id();

    private:
        int  port;
        char *tag;
        char *name;
        char *host;
        char *socket;
        char *username;
        char *password;
        char *charset;

        int parse_line_from_db_conf(char *line);   // Parses database connection info from the given file.
        int db_parse_root(char *feed);             // A parse-support function.
        void dbCleanup(void);                      // Take apart the database in an orderly fashion.

        char* str_n_dup(const char *s, size_t n);  // Makes a malloc'd copy of a binary string.
};


class GfxUIMySQL : public GfxUIElement {
  public:
    GfxUIMySQL(const GfxUILayout lay, const GfxUIStyle sty, MySQLConnector* db_con, uint32_t f = 0) : GfxUIElement(lay, sty, f | GFXUI_FLAG_ALWAYS_REDRAW), _db_con(db_con) {};
    ~GfxUIMySQL() {};

    /* Implementation of GfxUIElement. */
    virtual int  _render(UIGfxWrapper*);
    virtual bool _notify(const GfxUIEvent, uint32_t x, uint32_t y, PriorityQueue<GfxUIElement*>*);

  protected:
    MySQLConnector* _db_con;
};


#endif    // MYSQL_CONNECTOR_H
