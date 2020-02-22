#include <syslog.h>
#include <mysql/errmsg.h>
#include <mysql/mysql.h>
#include "MySQLConnector.h"
#include "StringBuilder.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

extern void fp_log(const char *fxn_name, int severity, const char *message, ...);

extern int causeParentToReloadMysql(void);


MySQLConnector::MySQLConnector() {
    this->db_connected = 0;
    this->port         = 0;
    this->tag          = nullptr;
    this->name         = nullptr;
    this->host         = nullptr;
    this->socket       = nullptr;
    this->username     = nullptr;
    this->password     = nullptr;
    this->charset      = nullptr;
    this->node_id      = nullptr;
    this->mysql        = nullptr;
    this->no_free_on_destructor = false;   // This should only be true in the parent.
}

MySQLConnector::~MySQLConnector() {
    this->dbCleanup();
    fp_log(__PRETTY_FUNCTION__, LOG_DEBUG, "MySQLConnector is beginning its free operation.");
    if (this->tag != nullptr) {        free(this->tag);        }
    if (this->name != nullptr) {       free(this->name);       }
    if (this->host != nullptr) {       free(this->host);       }
    if (this->socket != nullptr) {     free(this->socket);     }
    if (this->username != nullptr) {   free(this->username);   }
    if (this->password != nullptr) {   free(this->password);   }
    if (this->charset != nullptr) {    free(this->charset);    }
    if (this->node_id != nullptr) {    free(this->node_id);    }
    this->port       = 0;
    this->tag        = nullptr;
    this->name       = nullptr;
    this->host       = nullptr;
    this->socket     = nullptr;
    this->username   = nullptr;
    this->password   = nullptr;
    this->charset    = nullptr;
    this->mysql      = nullptr;
    fp_log(__PRETTY_FUNCTION__, LOG_INFO, "MySQLConnector finished its free operation.");
}


// A debug function. Prints the database connection details.
void MySQLConnector::print_db_conn_detail(){
    fp_log(__PRETTY_FUNCTION__, LOG_INFO, "Database connection data follows:");
    fp_log(__PRETTY_FUNCTION__, LOG_INFO, "==============================");
    if (this->tag != nullptr) {        fp_log(__PRETTY_FUNCTION__, LOG_INFO, "DB_TAG:   %s", this->tag);        }
    if (this->name != nullptr) {       fp_log(__PRETTY_FUNCTION__, LOG_INFO, "DB_NAME:  %s", this->name);       }
    if (this->host != nullptr) {       fp_log(__PRETTY_FUNCTION__, LOG_INFO, "HOST:     %s", this->host);       }
    if (this->port >= 0) {          fp_log(__PRETTY_FUNCTION__, LOG_INFO, "PORT:     %d", this->port);       }
    if (this->socket != nullptr) {     fp_log(__PRETTY_FUNCTION__, LOG_INFO, "SOCKET:   %s", this->socket);     }
    if (this->username != nullptr) {   fp_log(__PRETTY_FUNCTION__, LOG_INFO, "USERNAME: %s", this->username);   }
    if (this->password != nullptr) {   fp_log(__PRETTY_FUNCTION__, LOG_INFO, "PASSWORD: %s", this->password);   }
    if (this->charset != nullptr) {    fp_log(__PRETTY_FUNCTION__, LOG_INFO, "CHARSET:  %s", this->charset);    }
    fp_log(__PRETTY_FUNCTION__, LOG_INFO, "==============================");
}


/**
* Wrapper for queries that will make all reasonable efforts to get the query executed.
*    Returns 1 on success and 0 on failure.
*/
int MySQLConnector::r_query(unsigned char *query) {    return this->r_query((char *)query);    }
int MySQLConnector::r_query(const char *query) {       return this->r_query((char *)query);    }
int MySQLConnector::r_query(char *query) {
    int return_value = 0;

    if (this->dbConnected()) {
        if (mysql_query(this->mysql, query) != 0) {
           unsigned int err_no = mysql_errno(this->mysql);
           switch (err_no) {
               case 0:
                   this->result = mysql_store_result(this->mysql);
                   fp_log(__PRETTY_FUNCTION__, LOG_WARNING, "in query 1\n");
                   return_value    = 1;
                   break;
               case 2006:    // MySQL server has gone away.
                   if (causeParentToReloadMysql()) {
                       if (mysql_query(this->mysql, query)) {    // Try to re-run the failed query.
                           err_no = mysql_errno(this->mysql);
                           fp_log(__PRETTY_FUNCTION__, LOG_WARNING, "The following query caused error code %d (%s) after being run for the second time. Dropping the query: %s", err_no, mysql_error(this->mysql), query);
                       }
                   }
                   else fp_log(__PRETTY_FUNCTION__, LOG_WARNING, "DB failed a reload. The following query was permanently dropped: ", query);
                   break;
               default:
                   fp_log(__PRETTY_FUNCTION__, LOG_WARNING, "The following query caused error code %d (%s): %s", err_no, mysql_error(this->mysql), query);
                   break;
           }
        }
        else {
            this->result = mysql_store_result(this->mysql);
            return_value = 1;
        }
    }

    return return_value;
}


long MySQLConnector::escape_string(char* src, StringBuilder* dest) {
  if ((nullptr != src) && (nullptr != dest)) {
    long escaped_len = 0;
    long src_len = strlen(src);
    if (src_len > 0) {
      char escaped[(src_len * 2) + 1];
      escaped_len = mysql_real_escape_string(mysql, escaped, src, src_len);
      *(escaped + escaped_len) = '\0';
      dest->concat(escaped);
    }
    return escaped_len;
  }
  return -1;
}


int MySQLConnector::last_insert_id() {
  int return_value = -1;
  if (this->dbConnected()) {
    if (mysql_query(this->mysql, "SELECT LAST_INSERT_ID();") == 0) {
      MYSQL_RES *last_id_res = mysql_store_result(this->mysql);
      MYSQL_ROW row = mysql_fetch_row(last_id_res);
      return_value = atoi(row[0]);
      mysql_free_result(last_id_res);
    }
  }
  return return_value;
}



// Pass a line from the DB conf file and it shall be parsed and placed into the appropriate slot.
int MySQLConnector::parse_line_from_db_conf(char *line) {
    int   return_value    = -1;
    char* equal_pos      = strchr(line, '=');
    char* line_end       = strchr(line, '\n');
    if (equal_pos != nullptr) {
        while ((*(equal_pos) == ' ') || (*(equal_pos) == '=' )) {   equal_pos++;    }   // Trim

        if (strncmp("dbhost", line, 6) == 0) {
            this->host      = (char *)(intptr_t) str_n_dup(equal_pos, (line_end-equal_pos));
            return_value    = 0;
        }
        else if (strncmp("dbname", line, 6) == 0) {
            this->name      = (char *)(intptr_t) str_n_dup(equal_pos, (line_end-equal_pos));
            return_value    = 0;
        }
        else if (strncmp("dbuser", line, 6) == 0) {
            this->username  = (char *)(intptr_t) str_n_dup(equal_pos, (line_end-equal_pos));
            return_value    = 0;
        }
        else if (strncmp("dbpass", line, 6) == 0) {
            this->password  = (char *)(intptr_t) str_n_dup(equal_pos, (line_end-equal_pos));
            return_value    = 0;
        }
        else if (strncmp("dbport", line, 6) == 0) {         // This one has to be an integer parse.
            char *temp_str  = (char*) alloca((line_end-equal_pos)+1);
            memset(temp_str, 0, (line_end-equal_pos)+1);
            strncpy(temp_str, equal_pos, (line_end-equal_pos));
            this->port      = atoi(temp_str);
            return_value    = 0;
        }
        else if (strncmp("dbsock", line, 6) == 0) {
            this->socket    = (char *)(intptr_t) str_n_dup(equal_pos, (line_end-equal_pos));
            return_value    = 0;
        }
        else if (strncmp("dbcharset", line, 9) == 0) {
            this->charset   = (char *)(intptr_t) str_n_dup(equal_pos, (line_end-equal_pos));
            return_value    = 0;
        }
        else if (strncmp("node_id", line, 7) == 0) {
            this->node_id   = (char *)(intptr_t) str_n_dup(equal_pos, (line_end-equal_pos));
            return_value    = 0;
        }
    }
    return return_value;
}


// The root of the DB connection def parser.
// Returns -1 on failure or the number of lines parsed on success
int MySQLConnector::db_parse_root(char *feed){
  int  return_value   = -1;
  if (feed == nullptr) {
    fp_log(__PRETTY_FUNCTION__, LOG_WARNING, "Couldn't parse tag: %s", feed);
    return return_value;
  }
  int  feed_len       = strlen(feed);

  this->tag = str_n_dup(feed, feed_len-1);

  char *line_delim    =  strchr(feed, '\n');
    while ((line_delim != nullptr) && (strlen(line_delim) > 2)) {
        if (this->parse_line_from_db_conf((char *)(line_delim+1)) < 0) {
            fp_log(__PRETTY_FUNCTION__, LOG_WARNING, "Ignoring bad line in conf file: %s", ((char *)(line_delim+1)));
        }
        if (feed_len <= ((line_delim+1)-feed)) {
            line_delim = nullptr;
        }
        else {
            line_delim  =  strchr(line_delim+1, '\n');
        }
        return_value++;
    }
  return_value++; // To make it a natural number.
  return return_value;
}


// Call this method to read the given filename and parse its contents into the
//    DB connection struct.
int MySQLConnector::provisionConnectionDetails(char *filename) {
    int return_value    = -1;
    char *ok_filename;

    if ((filename == nullptr) || (strlen(filename) <= 0)) {        // If the provided filename is NULL, use the default.
        ok_filename    = strdupa(DEFAULT_CONF_FILE);
        fp_log(__PRETTY_FUNCTION__, LOG_NOTICE, "Using default configuration file: %s", ok_filename);
    }
    else{
        ok_filename    = filename;
    }

    FILE    *fp = fopen(ok_filename, "r");
    if (fp == nullptr) {
        fp_log(__PRETTY_FUNCTION__, LOG_WARNING, "Could not open (%s) for read-only access.\n", ok_filename);
        return return_value;
    }
    size_t  result, file_len;
    fseek(fp, 0, SEEK_END);
    file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *code = (char*) alloca((sizeof(char) * file_len) + 10);
    if (code == nullptr) {
            fp_log(__PRETTY_FUNCTION__, LOG_WARNING, "provisionConnectionDetails(): Failed to allocate %d bytes to read the DB connection data.", file_len);
            return return_value;
    }
    memset(code, 0x00, (sizeof(char) * file_len)+10);
    result = fread(code, 1, file_len, fp);
    if (result) {
      return_value    = this->db_parse_root(code);
    }
    fclose(fp);
    return return_value;
}




// Returns 1 on success (ready to query) and 0 on failure.
int MySQLConnector::dbConnected(){
    if (this->mysql == nullptr) {
        this->mysql = mysql_init(nullptr);
        if (this->mysql == nullptr) {
            fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Cannot connect to the MySQL server. This is a serious problem and will prevent us from running eventually.");
            this->db_connected = -1;
            return 0;
        }
    }
    if (this->db_connected != 1) {
        if (mysql_real_connect(this->mysql, this->host, this->username, this->password, this->name, this->port, nullptr, 0)) {
            StringBuilder temp_query((char *) "USE ");
            temp_query.concat(this->name);
            temp_query.concat(";");
            if (mysql_query(this->mysql, (const char*)temp_query.string()) != 0) {
                fp_log(__PRETTY_FUNCTION__, LOG_NOTICE, "Failed to select %s as a database.", this->name);
            }
            else {
                mysql_autocommit(this->mysql, 1);
                this->db_connected = 1;
                fp_log(__PRETTY_FUNCTION__, LOG_NOTICE, "Connected to database %s.", this->name);
            }
        }
        else {
            this->db_connected = 0;
            char *tmp_str    = (char *) mysql_error(this->mysql);
            fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to connect to MySQL: %s", tmp_str);
            this->print_db_conn_detail();
            this->db_connected    = -1;
        }
    }
    return this->db_connected;
}



// Call to wrap up any DB-related things so that we can exit clean.
void MySQLConnector::dbCleanup() {
    if (this->mysql == nullptr) {
        fp_log(__PRETTY_FUNCTION__, LOG_WARNING, "We do not seem to have a MySQL server.");
    }
    else {
        if (!this->no_free_on_destructor) {
            fp_log(__PRETTY_FUNCTION__, LOG_INFO, "Closing connection to MySQL server.");
            mysql_close(this->mysql);
        }
        else {
            fp_log(__PRETTY_FUNCTION__, LOG_DEBUG, "This object was copied from a parent process. Declining to close the MySQL connection.");
        }
        this->db_connected = 0;
        this->mysql = nullptr;
    }
}


// Return a malloc'd copy of the trimmed input string.
char* MySQLConnector::str_n_dup(const char *s, size_t n) {
    size_t i    = 0;
    char *r = (char *) malloc(n+1);
    memset(r, 0, (n+1));

    while (i < n) {
        *(r + i) = *(s + i);
        i++;
    }
    r[i]    = '\0';
    char *end = r + strlen(r) - 1;
    while (end > r && isspace(*end)) end--;
    *(end+1) = 0;
    return r;
}
