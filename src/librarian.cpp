/*
* Author:    J. Ian Lindsay
*
*
*
* VERSION HISTORY:
* ========================================================================================================================
* 0.0.1:      First operational version. Must take operating args from command line.
*/

#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <fstream>
#include <iostream>

#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <netdb.h>

#include <uuid/uuid.h>
#include <mysql/mysql.h>
#include <openssl/evp.h>

#include "MySQLConnector/DBAbstractions/ORM.h"
#include "ConfigManager/ConfigManager.h"

#include "DataStructures/LightLinkedList.h"
#include "DataStructures/PriorityQueue.h"
#include "DataStructures/StringBuilder.h"

using namespace std;



#define FP_VERSION "0.0.1"

#ifndef max
    #define max( a, b ) ( ((a) > (b)) ? (a) : (b) )
#endif

#ifndef min
    #define min( a, b ) ( ((a) < (b)) ? (a) : (b) )
#endif


const int BUFFER_LEN       = 8192;      // This is the maximum size of any given packet we can handle.
const int INTERRUPT_PERIOD = 1;        // How many seconds between SIGALRM interrupts?

int continue_listening  = 1;
int parent_pid          = 0;            // The PID of the root process (always).
int pd_pid;                             // This is the PID for the dialplan thread.

LibrarianDB db;
ConfigManager conf;
ORMDatahiveVersion* root_catalog = nullptr;

char *program_name;
int maximum_field_print = 65;         // The maximum number of bytes we will print for sessions. Has no bearing on file output.

// The maximum size of user input.
#define U_INPUT_BUFF_SIZE 128



/****************************************************************************************************
* Function prototypes...                                                                            *
****************************************************************************************************/
void fp_log(const char *fxn_name, int severity, const char *message, ...);
int causeParentToReloadMysql(void);

void printCatalogInfo();


/****************************************************************************************************
* Utilities...                                                                                      *
****************************************************************************************************/

/*
* Writes the given bit string into a character buffer as a hex representation.
* len in the number of bytes to read from str.
*/
char* printBinStringToBuffer(unsigned char *str, int len, char *buffer) {
  if (buffer != NULL) {
  int i = 0;
    unsigned int moo  = 0;
    if ((str != NULL) && (len > 0)) {
      for (i = 0; i < len; i++) {
        moo  = *(str + i);
        sprintf((buffer+(i*2)), "%02x", moo);
      }
    }
  }
  return buffer;
}


/*
* Perform a SHA256 digest.
* It is the responsibility of the caller to ensure that the return buffer has enough space allocated
*   to receive the digest.
* Returns 1 on success and 0 on failure.
*/
int PROC_SHA256_MSG(unsigned char *msg, long msg_len, unsigned char *md, unsigned int md_len) {
  int return_value    = 0;
  const EVP_MD *evp_md  = EVP_sha256();
  memset(md, 0, md_len);

  if (evp_md != NULL) {
    EVP_MD_CTX *cntxt = (EVP_MD_CTX *)(intptr_t) EVP_MD_CTX_create();
    EVP_DigestInit(cntxt, evp_md);
    if (msg_len > 0) EVP_DigestUpdate(cntxt, msg, msg_len);
    EVP_DigestFinal_ex(cntxt, md, &md_len);
    EVP_MD_CTX_destroy(cntxt);
    return_value  = 1;
  }
  else {
    fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to load the digest algo SHA256.");
  }
  return return_value;
}


/*
* Function takes a path and a buffer as arguments. The binary is hashed and the ASCII representation is
*   placed in the buffer. The number of bytes read is returned on success. 0 is returned on failure.
*/
long hashFileByPath(char *path, char *h_buf) {
  long return_value    = 0;
  ifstream self_file(path, ios::in | ios::binary | ios::ate);
  if (self_file) {
    long self_size = self_file.tellg();

    char *self_mass   = (char *) alloca(self_size);
    int digest_size = 32;
    unsigned char *self_digest = (unsigned char *) alloca(digest_size);
    memset(self_digest, 0x00, digest_size);
    memset(self_mass, 0x00, self_size);
    self_file.seekg(0);   // After checking the file size, make sure to reset the read pointer...
    self_file.read(self_mass, self_size);
    fp_log(__PRETTY_FUNCTION__, LOG_INFO, "%s is %d bytes.", path, self_size);

    if (PROC_SHA256_MSG((unsigned char *) self_mass, self_size, self_digest, digest_size)) {
      memset(h_buf, 0x00, 65);
      printBinStringToBuffer(self_digest, 32, h_buf);
      fp_log(__PRETTY_FUNCTION__, LOG_INFO, "This binary's SHA256 fingerprint is %s.", h_buf);
      return_value = self_size;
    }
    else {
      fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to run the hash on the input path.");
    }
  }
  return return_value;
}


/*
*
*/
void cleanupCatalog() {
  if (nullptr != root_catalog) {
    printf("Clearing current metadata...\n");
    delete root_catalog;
    root_catalog = nullptr;
  }
  else {
    printf("No catalog.\n");
  }
}


/*
* start cataloging the files recursively.
*/
long startCatalogScan() {
  long return_value = 0;
  if (root_catalog) {
    return_value = root_catalog->scan();
    printf("Scan finished.\n");
    printCatalogInfo();
  }
  else {
    printf("No catalog.\n");
    return_value = -1;
  }
  return return_value;
}


/*
* Given a path, create a new catalog.
*/
long newCatalogPath(char* root) {
  long return_value = -1;
  if (nullptr != root_catalog) {
    cleanupCatalog();
  }
  root_catalog = new ORMDatahiveVersion(23, root);
  if (root_catalog) {
    LibrarianDB* _db = LibrarianDB::getInstance();
    StringBuilder insert_query;
    root_catalog->generateInsertQuery(&insert_query);
    if (1 == _db->r_query(insert_query.string())) {
      root_catalog->markClean();
    }
    else {
      fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to save record to database.");
      printf("%s\n", (char*) insert_query.string());
    }
    StringBuilder tmp("Created new catalog:\n");
    root_catalog->printDebug(&tmp);
    printf("%s\n", tmp.string());
    return_value = 0;
  }
  else {
    fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to instantiate ORMDatahiveVersion for root.");
  }
  return return_value;
}


/****************************************************************************************************
* String processing functions.                                                                      *
****************************************************************************************************/

/*  Trim the whitespace from the beginning and end of the input string.
*  Should not be used on malloc'd space, because it will eliminate the
*    reference to the start of an allocated range which must be freed.
*/
char* trim(char *str) {
  char *end;
  while(isspace(*str)) str++;
  if(*str == 0) return str;
  end = str + strlen(str) - 1;
  while(end > str && isspace(*end)) end--;
  *(end+1) = '\0';
  return str;
}


// A debug function that prints the given number of integer values of a given binary string.
void printBinString(unsigned char * str, int len) {
    int i = 0;
    char *temp  = (char *) alloca(len * 4);
    char *temp0 = (char *) alloca(10);
    bzero(temp, len*4);
    bzero(temp0, 10);
    if ((temp != NULL) && (temp0 != NULL) && (str != NULL) && (len > 0)) {
        temp[0] = '\0';
        for (i = 0; i < len; i++) {
            sprintf(temp0, "%d ", *(str + i));
            strcat(temp, temp0);
        }
        strcat(temp, "\n");
        fp_log(__PRETTY_FUNCTION__, LOG_INFO, temp);
    }
}


/**
* Send a signal to the parent process to reload the database.
*  Returns 1 on success and 0 on failure.
*/
int causeParentToReloadMysql() {
  if (kill(parent_pid, SIGUSR2)) {        // Did it fail?
    fp_log(__PRETTY_FUNCTION__, LOG_WARNING, "We failed to send a signal to pid %d, which we believe to be our parent process.", parent_pid);
    return 0;
  }
  db.db_connected = 0;     // Sending the signal will only benefit the children that fork later on. In order for our connection
  db.mysql = NULL;         // to be good, we need to re-establish it ourselves. Don't be too concerned about memory, as this PID will be reaped.
  return db.dbConnected();
}



/****************************************************************************************************
* Logging-related functions.                                                                        *
****************************************************************************************************/

// Returns 1 if we ought to be logging to the fp_log.
//    Since this is our default logging target, we will response 'yes' even if the DB isn't loaded.
int shouldLogToSyslog() {
    int return_value    = conf.getConfigIntByKey("log-to-syslog");
    if (return_value == -1) {
        return_value    = 1;
    }
    return return_value;
}


int shouldLogToStdout() {
    int return_value    = conf.getConfigIntByKey("log-to-stdout");
    if (return_value == -1) {
        return_value    = 0;
    }
    return return_value;
}


int shouldLogToDatabase() {
    int return_value    = conf.getConfigIntByKey("log-to-database");
    if (return_value == -1) {
        return_value    = 0;
    }
    return return_value;
}



// Log a message. Target is determined by the current_config.
//    If no logging target is specified, log to stdout.
void fp_log(const char *fxn_name, int severity, const char *str, ...) {
  va_list marker;
  char *temp_buf = (char *) alloca(4096);
  bzero(temp_buf, 4096);
  va_start(marker, str);
  vsprintf(temp_buf, str, marker);
  va_end(marker);

  int log_disseminated    = 0;
  time_t seconds = time(NULL);
  char *time_str    = (char *) alloca(32);
  strftime(time_str, 32, "%c", gmtime(&seconds));
  if (shouldLogToSyslog()) {
    syslog(severity, "%s", temp_buf);
    log_disseminated    = 1;
  }

  if ((log_disseminated != 1) || shouldLogToStdout()){
    printf("%s\n", temp_buf);
  }
}




/****************************************************************************************************
* Functions that just print things.                                                                 *
****************************************************************************************************/

/*
* Print the loaded catalog.
*/
void printCatalogInfo() {
  if (root_catalog) {
    StringBuilder tmp;
    root_catalog->printDebug(&tmp);
    printf("%s\n", tmp.string());
  }
  else {
    printf("No catalog.\n");
  }
}


/*
*  Prints a list of valid commands.
*/
void printHelp() {
  printf("==< HELP >=========================================================================================\n");
  printf("%s    Build date:  %s %s\n", program_name, __DATE__, __TIME__);
  printf("'catalog'     Create a new catalog at the given path.\n");
  printf("'tag'         Set a tag for the catalog.\n");
  printf("'notes'       Set the notes on the catalog.\n");
  printf("'scan'        Read the filesystem to fill out the catalog.\n");
  printf("'unload'      Discard the current catalog.\n");
  printf("'help'        This.\n");
  printf("'quit'        Bail? Bail.\n");
  printf("==< HELP >=============================================================================< v%5s >==\n", FP_VERSION);
  printf("\n\n");
}


/**
* The help function. We use printf() because we are certain there is a user at the other end of STDOUT.
*/
void printUsage() {
  printf("-v  --version       Print the version and exit.\n");
  printf("-h  --help          Print this output and exit.\n");
  printf("    --verbosity     How noisy should we be in the logs?\n");
  printf("-c  --conf          Manually specify a file containing the database connection parameters.\n");
  printf("                      Default value if not supplied is %s.\n", DEFAULT_CONF_FILE);
  printf("\n\n");
}



/****************************************************************************************************
* Signal catching code.                                                                             *
****************************************************************************************************/
void sig_handler(int signo) {
    switch (signo) {
        case SIGINT:
          fp_log(__PRETTY_FUNCTION__, LOG_NOTICE, "Received a SIGINT signal. Closing up shop...");
          break;
        case SIGKILL:
          fp_log(__PRETTY_FUNCTION__, LOG_NOTICE, "Received a SIGKILL signal. Something bad must have happened. Exiting hard....");
          exit(1);
          break;
        case SIGTERM:
          fp_log(__PRETTY_FUNCTION__, LOG_NOTICE, "Received a SIGTERM signal. Closing up shop...");
          break;
        case SIGQUIT:
          fp_log(__PRETTY_FUNCTION__, LOG_NOTICE, "Received a SIGQUIT signal. Closing up shop...");
          break;
        case SIGHUP:
          fp_log(__PRETTY_FUNCTION__, LOG_NOTICE, "Received a SIGHUP signal. Closing up shop...");
          break;
        case SIGSTOP:
           fp_log(__PRETTY_FUNCTION__, LOG_NOTICE, "Received a SIGSTOP signal. Closing up shop...");
           break;
        case SIGUSR1:      // Cause a configuration reload.
          fp_log(__PRETTY_FUNCTION__, LOG_NOTICE, "USR1 received.");
          break;
        case SIGUSR2:    // Cause a database reload.
           fp_log(__PRETTY_FUNCTION__, LOG_NOTICE, "USR2 received.");
          break;
        default:
          fp_log(__PRETTY_FUNCTION__, LOG_NOTICE, "Unhandled signal: %d", signo);
          break;
    }
}



// The parent process should call this function to set the callback address to its signal handlers.
//     Returns 1 on success, 0 on failure.
int initSigHandlers() {
    int return_value    = 1;
    // Try to open a binding to listen for signals from the OS...
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to bind SIGINT to the signal system. Failing...");
        return_value = 0;
    }
    if (signal(SIGQUIT, sig_handler) == SIG_ERR) {
        fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to bind SIGQUIT to the signal system. Failing...");
        return_value = 0;
    }
    if (signal(SIGHUP, sig_handler) == SIG_ERR) {
        fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to bind SIGHUP to the signal system. Failing...");
        return_value = 0;
    }
    if (signal(SIGTERM, sig_handler) == SIG_ERR) {
        fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to bind SIGTERM to the signal system. Failing...");
        return_value = 0;
    }
    if (signal(SIGUSR1, sig_handler) == SIG_ERR) {
        fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to bind SIGUSR1 to the signal system. Failing...");
        return_value = 0;
    }
    if (signal(SIGUSR2, sig_handler) == SIG_ERR) {
        fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to bind SIGUSR2 to the signal system. Failing...");
        return_value = 0;
    }
    if (signal(SIGALRM, sig_handler) == SIG_ERR) {
        fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to bind SIGALRM to the signal system. Failing...");
        return_value = 0;
    }
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
        fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to bind SIGCHLD to the signal system. Failing...");
        continue_listening  = 0;
    }
    return return_value;
}



/****************************************************************************************************
* Entry-point                                                                                       *
****************************************************************************************************/

int main(int argc, char *argv[]) {
  char *db_conf_filename  = NULL;     // Where should we look for our DB parameters?
  program_name            = argv[0];  // Our name.
  int running  = 1;

  srand(time(NULL));          // Seed the PRNG...

  // If we don't have these conf keys, we can't do our jaerb...
  conf.setRequiredConfKeys(1, "verbosity");

  openlog(argv[0], LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);   // Set up our logging faculty...

  // Parse through all the command line arguments and flags...
  // Please note that the order matters. Put all the most-general matches at the bottom of the loop.
  for (int i = 1; i < argc; i++) {
    if ((strcasestr(argv[i], "--help")) || (strcasestr(argv[i], "-h"))) {
      printUsage();
      exit(0);
    }
    else if ((strcasestr(argv[i], "--version")) || (strcasestr(argv[i], "-v") == argv[i])) {
      printf("%s v%s\n\n", argv[0], FP_VERSION);
      exit(0);
    }
    else if (argc - i >= 2) {    // Compound arguments go in this case block...
      if ((strcasestr(argv[i], "--conf")) || (strcasestr(argv[i], "-c"))) {
        if (argc - i < 2) {  // Mis-use of flag...
          printUsage();
          exit(1);
        }
        i++;
        db_conf_filename = argv[i++];
      }
      else if ((strlen(argv[i]) > 3) && (argv[i][0] == '-') && (argv[i][1] == '-')) {
        // Insert a new conf item...
        conf.insertConfigItem((const char*)(argv[i]+2), argv[i+1], false);
        i++;
      }
      else {
        i++;
      }
    }
    else {
      printf("Unhandled argument: %s\n", argv[i]);
      printUsage();
      exit(1);
    }
  }

  parent_pid = getpid();                                        // We will need to know our root PID.
  initSigHandlers();

  // Once we have those things, we can ask MySQL for the bulk of the config, and set up whatever else we need for our purpose...
  if (db.provisionConnectionDetails(db_conf_filename) >= 0) {            // Need to know which DB to connect with.
    db.print_db_conn_detail();          // Writes the connection data to the log.
    if (1 != db.dbConnected()) {
      fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Failed to connect to database. Stopping...");
      exit(1);
    }
    //conf.loadConfigFromDb(&db);         // Load config from the DB.
  }
  else {
    fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Couldn't parse DB conf from %s. Stopping...", ((db_conf_filename == NULL) ? DEFAULT_CONF_FILE : db_conf_filename));
  }

  //// Alright... we are done loading configuration. Now let's make sure it is complete...
  //if (!conf.isConfigComplete()) {
  //    fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Configuration is incomplete. Shutting down...");
  //    exit(1);
  //}
  //setlogmask(LOG_UPTO(conf.getConfigIntByKey("verbosity")));  // Set the log mask to the user's preference.


    /* INTERNAL INTEGRITY-CHECKS
    *  Now... at this point, with our config complete and a database at our disposal, we do some administrative checks...
    *  The first task is to look in the mirror and find our executable's full path. This will vary by OS, but for now we
    *  assume that we are on a linux system.... */
    char *exe_path = (char *) alloca(512);   // 512 bytes ought to be enough for our path info...
    memset(exe_path, 0x00, 512);
    int exe_path_len = readlink("/proc/self/exe", exe_path, 512);
    if (!(exe_path_len > 0)) {
        fp_log(__PRETTY_FUNCTION__, LOG_ERR, "%s was unable to read its own path from /proc/self/exe. You may be running it on an unsupported operating system, or be running an old kernel. Please discover the cause and retry. Exiting...", program_name);
        exit(1);
    }
    fp_log(__PRETTY_FUNCTION__, LOG_INFO, "This binary's path is %s", exe_path);

    // Now to hash ourselves...
    char *h_buf = (char *)alloca(65);
    memset(h_buf, 0x00, 65);
    hashFileByPath(exe_path, h_buf);

    //// If we've stored a hash for our binary, compare it with the hash we calculated. Make sure they match. Pitch a fit if they don't.
    //if (conf.configKeyExists("binary-hash")) {
    //    if (strcasestr(h_buf, conf.getConfigStringByKey("binary-hash")) == NULL) {
    //      fp_log(__PRETTY_FUNCTION__, LOG_ERR, "Calculated hash value does not match what was stored in your config. Exiting...");
    //      exit(1);
    //    }
    //}
    ///* INTERNAL INTEGRITY-CHECKS */

  char *input_text  = (char*) alloca(U_INPUT_BUFF_SIZE);  // Buffer to hold user-input.
  char *pos0;            // Temporary pointers for manipulating user-input.
  StringBuilder parsed;

  // The main loop. Run forever.
  while (running) {
    printf("%c[36m%s> %c[39m", 0x1B, argv[0], 0x1B);
    bzero(input_text, U_INPUT_BUFF_SIZE);
    if (fgets(input_text, U_INPUT_BUFF_SIZE, stdin) != NULL) {
      parsed.concat(input_text);
      parsed.split(" ");

      pos0 = parsed.position(0);

      // Begin the cases...
      if (strlen(pos0) <= 1)                printCatalogInfo(); // User entered nothing.
      else if (strcasestr(pos0, "QUIT"))    running = 0;        // Exit
      else if (strcasestr(pos0, "HELP"))    printHelp();        // Show help.
      else if (strcasestr(pos0, "SCAN"))    startCatalogScan(); // Accumulate metadata.
      else if (strcasestr(pos0, "UNLOAD"))  cleanupCatalog();   // Unload metadata.

      else if (strcasestr(pos0, "MAX-WIDTH"))  {
        if (parsed.count() > 1) {
          maximum_field_print = parsed.position_as_int(1);
          if (maximum_field_print <= 0) {
            printf("You tried to set the output width as 0. This is a bad idea. Setting the value to 64 instead.\n");
            maximum_field_print = 64;
          }
        }
        else {
          printf("max-width is presently set to %d.\n", maximum_field_print);
        }
      }
      else if (strcasestr(pos0, "CATALOG"))  {
        if (parsed.count() > 1) {
          newCatalogPath(parsed.position(1));
        }
        else {
          printf("Catalog needs a path to take as a root.\n");
        }
      }
      else if (strcasestr(pos0, "TAG"))  {
        if ((nullptr != root_catalog) && (parsed.count() > 1)) {
          parsed.drop_position(0);  // Throw away the command.
          root_catalog->setTag(&parsed);
        }
        else {
          printf("No catalog, and/or no notes.\n");
        }
      }
      else if (strcasestr(pos0, "NOTES"))  {
        if ((nullptr != root_catalog) && (parsed.count() > 1)) {
          parsed.drop_position(0);  // Throw away the command.
          parsed.implode(" ");
          root_catalog->setNotes(&parsed);
        }
        else {
          printf("No catalog, and/or no notes.\n");
        }
      }
      else {  // Any other input, we will print the help.
        printHelp();
      }
      parsed.clear();
    }
    else {
      printHelp();
    }
  }

  fp_log(__PRETTY_FUNCTION__, LOG_INFO, "Stopping...");
  if (nullptr != root_catalog) {
    delete root_catalog;
    root_catalog = nullptr;
  }

  exit(0);
}
