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

#include "LightLinkedList.h"
#include "PriorityQueue.h"
#include "StringBuilder.h"
#include "CppPotpourri.h"
#include "ParsingConsole.h"
#include "Identity/Identity.h"

#include <Linux.h>

#define FP_VERSION         "0.0.4"    // Program version.
#define U_INPUT_BUFF_SIZE     8192    // The maximum size of user input.

using namespace std;

const int INTERRUPT_PERIOD = 1;        // How many seconds between SIGALRM interrupts?

int continue_running  = 1;
int parent_pid          = 0;            // The PID of the root process (always).
int pd_pid;                             // This is the PID for the worker thread.

LibrarianDB db;
ConfigManager conf;
ORMDatahiveVersion* root_catalog = nullptr;

char* program_name;
int maximum_field_print = 65;         // The maximum number of bytes we will print for sessions. Has no bearing on file output.

/* Console junk... */
ParsingConsole console(U_INPUT_BUFF_SIZE);
LinuxStdIO console_adapter;



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
  root_catalog = new ORMDatahiveVersion(root);
  if (root_catalog) {
    root_catalog->commit();
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


/**
* The help function for invocation. We use printf() because we are
*   certain there is a user at the other end of STDOUT.
*/
void printUsage() {
  printf("-v  --version       Print the version and exit.\n");
  printf("-h  --help          Print this output and exit.\n");
  printf("    --verbosity     How noisy should we be in the logs?\n");
  printf("-c  --conf          Manually specify a file containing the database connection parameters.\n");
  printf("                      Default value if not supplied is %s.\n", DEFAULT_CONF_FILE);
  printf("\n\n");
}


/*******************************************************************************
* Console callbacks
*******************************************************************************/

int callback_help(StringBuilder* text_return, StringBuilder* args) {
  text_return->concatf("%s %s\n", program_name, FP_VERSION);
  if (0 < args->count()) {
    console.printHelp(text_return, args->position_trimmed(0));
  }
  else {
    console.printHelp(text_return);
  }
  return 0;
}

int callback_print_history(StringBuilder* text_return, StringBuilder* args) {
  console.printHistory(text_return);
  return 0;
}

int callback_program_quit(StringBuilder* text_return, StringBuilder* args) {
  continue_running = 0;
  return 0;
}

int callback_catalog_info(StringBuilder* text_return, StringBuilder* args) {
  printCatalogInfo();
  return 0;
}

int callback_start_scan(StringBuilder* text_return, StringBuilder* args) {
  startCatalogScan(); // Accumulate metadata.
  return 0;
}

int callback_unload(StringBuilder* text_return, StringBuilder* args) {
  cleanupCatalog();   // Unload metadata.
  return 0;
}

int callback_max_print_width(StringBuilder* text_return, StringBuilder* args) {
  if (0 < args->count()) {
    maximum_field_print = args->position_as_int(0);
    if (maximum_field_print <= 0) {
      text_return->concatf("You tried to set the output width as 0. This is a bad idea. Setting the value to 64 instead.\n");
      maximum_field_print = 64;
    }
  }
  else {
    text_return->concatf("max-width is presently set to %d.\n", maximum_field_print);
  }
  return 0;
}


int callback_new_catalog(StringBuilder* text_return, StringBuilder* args) {
  if (0 < args->count()) {
    newCatalogPath(args->position(0));
  }
  else {
    text_return->concat("Catalog needs a path to take as a root.\n");
  }
  return 0;
}


int callback_set_tag(StringBuilder* text_return, StringBuilder* args) {
  if (nullptr != root_catalog) {
    root_catalog->setTag(args);
  }
  else {
    text_return->concat("No catalog.\n");
  }
  return 0;
}


int callback_set_notes(StringBuilder* text_return, StringBuilder* args) {
  if (nullptr != root_catalog) {
    args->implode(" ");
    root_catalog->setNotes(args);
  }
  else {
    text_return->concat("No catalog.\n");
  }
  return 0;
}


int callback_conf_tools(StringBuilder* text_return, StringBuilder* args) {
  // char* cmd = args->position_trimmed(0);
  // char* key = args->position_trimmed(1);
  // char* val = args->position_trimmed(2);
  // UserConf user_conf;
  //
  // text_return->concat("\n");
  // if (0 == StringBuilder::strcasecmp(cmd, "val")) {
  //   switch (args->count()) {
  //     case 3:
  //       text_return->concatf(
  //         "Setting key %s to %s returns %d.\n",
  //         key, val, user_conf.setConf((const char*) key, val)
  //       );
  //       break;
  //     default:
  //       user_conf.printConf(text_return, (1 < args->count()) ? key : nullptr);
  //       break;
  //   }
  // }
  // else if (0 == StringBuilder::strcasecmp(cmd, "pack")) {
  //   // Tool for serializing conf into buffers. Should support CBOR and BINARY,
  //   //   for interchange and local storage, respectively.
  //   StringBuilder ser_out;
  //   TCode fmt = TCode::BINARY;
  //   int8_t ret = 0;
  //   if (2 == args->count()) {
  //     if (0 == StringBuilder::strcasecmp(key, "cbor")) {
  //       fmt = TCode::CBOR;
  //     }
  //     else if (0 == StringBuilder::strcasecmp(key, "bin")) {
  //       fmt = TCode::BINARY;
  //     }
  //     else {
  //       ret = -1;
  //     }
  //     if (0 == ret) {
  //       ret = user_conf.serialize(&ser_out, fmt);
  //       if (0 != ret) {
  //         text_return->concatf("Conf serializer returned %d.\n", ret);
  //       }
  //     }
  //   }
  //
  //   if (0 < ser_out.length()) {
  //     text_return->concatf("\n---< Conf >-------------------------------\n");
  //     StringBuilder::printBuffer(text_return, ser_out.string(), ser_out.length(), "\t");
  //   }
  //   else {
  //     text_return->concat("Usage: pack [cbor|bin]\n");
  //   }
  // }
  // else if (0 == StringBuilder::strcasecmp(cmd, "save")) {
  //   if (1 == args->count()) {
  //     text_return->concatf("Saving %s returned %d.\n", key, user_conf.save(key));
  //   }
  //   else {
  //     text_return->concat("Usage: save\n");
  //   }
  // }
  // else if (0 == StringBuilder::strcasecmp(cmd, "load")) {
  //   if (1 == args->count()) {
  //     text_return->concatf("Loading %s returned %d.\n", key, user_conf.load(key));
  //   }
  //   else {
  //     text_return->concat("Usage: load\n");
  //   }
  // }
  // else {
  //   text_return->concat("First argument must be the subcommand (val, pack, save, load).\n");
  // }
  return 0;
}


/****************************************************************************************************
* Entry-point                                                                                       *
****************************************************************************************************/

int main(int argc, char *argv[]) {
  char *db_conf_filename  = NULL;     // Where should we look for our DB parameters?
  program_name            = argv[0];  // Our name.
  StringBuilder output;

  platform.init();

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

  parent_pid = getpid();    // We will need to know our root PID.

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
    char* exe_path = (char *) alloca(512);   // 512 bytes ought to be enough for our path info...
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

  // Mutually connect the console class to STDIO.
  console_adapter.readCallback(&console);
  console.setOutputTarget(&console_adapter);

  // We want to have a nice prompt string...
  StringBuilder prompt_string;
  prompt_string.concatf("%c[36m%s> %c[39m", 0x1B, argv[0], 0x1B);
  console.setPromptString((const char*) prompt_string.string());

  console.defineCommand("help",        '?', ParsingConsole::tcodes_str_1, "Prints help to console.", "", 0, callback_help);
  console.defineCommand("history",     ParsingConsole::tcodes_0, "Print command history.", "", 0, callback_print_history);
  console.defineCommand("pfinfo",      ParsingConsole::tcodes_str_1,  "Platform information", "[subgroup]", 0, callback_platform_info);
  console.defineCommand("info",        'i', ParsingConsole::tcodes_str_1, "Print the catalog's vital stats.", "", 0, callback_catalog_info);
  console.defineCommand("scan",        ParsingConsole::tcodes_str_1, "Read the filesystem to fill out the catalog.", "", 0, callback_start_scan);
  console.defineCommand("unload",      ParsingConsole::tcodes_str_1, "Discard the current catalog.", "", 0, callback_unload);
  console.defineCommand("max-print",   ParsingConsole::tcodes_str_1, "Sets the maximum print width.", "", 0, callback_max_print_width);
  console.defineCommand("catalog",     ParsingConsole::tcodes_str_1, "Create a new catalog at the given path.", "", 1, callback_new_catalog);
  console.defineCommand("tag",         ParsingConsole::tcodes_str_1, "Set a tag for the catalog.", "", 1, callback_set_tag);
  console.defineCommand("notes",       ParsingConsole::tcodes_str_1, "Set the notes on the catalog.", "", 1, callback_set_notes);
  console.defineCommand("conf",        'c', ParsingConsole::tcodes_str_3, "Dump/set conf key.", "[conf_key] [value]", 1, callback_conf_tools);
  console.defineCommand("quit",        'Q', ParsingConsole::tcodes_0, "Commit sudoku.", "", 0, callback_program_quit);
  console.setTXTerminator(LineTerm::LF);
  console.setRXTerminator(LineTerm::LF);
  console.localEcho(false);
  console.emitPrompt(true);
  console.hasColor(true);
  console.init();

  output.concatf("%s initialized.\n", argv[0]);
  console.printToLog(&output);
  console.printPrompt();

  // The main loop. Run until told to stop.
  while (continue_running) {
    console_adapter.poll();
  }

  output.concat("Stopping nicely...\n");
  console.printToLog(&output);

  if (nullptr != root_catalog) {
    delete root_catalog;
    root_catalog = nullptr;
  }

  platform.firmware_shutdown(0);
}
