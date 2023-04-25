/*
* Author:    J. Ian Lindsay
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

//#include <uuid/uuid.h>
#include <mysql/mysql.h>
#include <openssl/evp.h>

#include "librarian.h"


#define U_INPUT_BUFF_SIZE    8192   // The maximum size of user input.
#define CONSOLE_INPUT_HEIGHT  200
#define TEST_FILTER_DEPTH     600
#define ELEMENT_MARGIN          5


/*******************************************************************************
* Globals
*******************************************************************************/
using namespace std;

const char*    program_name;
int            max_field_print   = 65;    // The maximum number of bytes we will print for sessions. Has no bearing on file output.
int            parent_pid        = 0;     // The PID of the root process (always).
int            pd_pid;                    // This is the PID for the worker thread.
bool           continue_running  = true;
MainGuiWindow* c3p_root_window   = nullptr;

LibrarianDB db;
ConfigManager conf;
ORMDatahiveVersion* root_catalog = nullptr;

/* Console junk... */
ParsingConsole console(U_INPUT_BUFF_SIZE);
LinuxStdIO console_adapter;

SensorFilter<uint32_t> test_filter_0(TEST_FILTER_DEPTH, FilteringStrategy::RAW);
SensorFilter<float> test_filter_1(TEST_FILTER_DEPTH, FilteringStrategy::RAW);
SensorFilter<float> test_filter_stdev(TEST_FILTER_DEPTH, FilteringStrategy::RAW);


MouseButtonDef mouse_buttons[] = {
  { .label = "Left",
    .button_id = 1,
    .gfx_event_down = GfxUIEvent::TOUCH,
    .gfx_event_up   = GfxUIEvent::RELEASE
  },
  { .label = "Middle",
    .button_id = 2,
    .gfx_event_down = GfxUIEvent::DRAG,
    .gfx_event_up   = GfxUIEvent::NONE
  },
  { .label = "Right",
    .button_id = 3,
    .gfx_event_down = GfxUIEvent::SELECT,
    .gfx_event_up   = GfxUIEvent::NONE
  },
  { .label = "ScrlUp",
    .button_id = 4,
    .gfx_event_down = GfxUIEvent::MOVE_UP,
    .gfx_event_up   = GfxUIEvent::NONE
  },
  { .label = "ScrlDwn",
    .button_id = 5,
    .gfx_event_down = GfxUIEvent::MOVE_DOWN,
    .gfx_event_up   = GfxUIEvent::NONE
  },
  { .label = "TiltLeft",
    .button_id = 6,
    .gfx_event_down = GfxUIEvent::MOVE_LEFT,
    .gfx_event_up   = GfxUIEvent::NONE
  },
  { .label = "TiltRight",
    .button_id = 7,
    .gfx_event_down = GfxUIEvent::MOVE_RIGHT,
    .gfx_event_up   = GfxUIEvent::NONE
  }
};



/****************************************************************************************************
* Function prototypes...                                                                            *
****************************************************************************************************/
int causeParentToReloadMysql();
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
    c3p_log(LOG_LEV_ERROR, __PRETTY_FUNCTION__, "Failed to load the digest algo SHA256.");
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
    c3p_log(LOG_LEV_INFO, __PRETTY_FUNCTION__, "%s is %d bytes.", path, self_size);

    if (PROC_SHA256_MSG((unsigned char *) self_mass, self_size, self_digest, digest_size)) {
      memset(h_buf, 0x00, 65);
      printBinStringToBuffer(self_digest, 32, h_buf);
      c3p_log(LOG_LEV_INFO, __PRETTY_FUNCTION__, "This binary's SHA256 fingerprint is %s.", h_buf);
      return_value = self_size;
    }
    else {
      c3p_log(LOG_LEV_ERROR, __PRETTY_FUNCTION__, "Failed to run the hash on the input path.");
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
    c3p_log(LOG_LEV_ERROR, __PRETTY_FUNCTION__, "Failed to instantiate ORMDatahiveVersion for root.");
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
        c3p_log(LOG_LEV_INFO, __PRETTY_FUNCTION__, temp);
    }
}


/**
* Send a signal to the parent process to reload the database.
*  Returns 1 on success and 0 on failure.
*/
int causeParentToReloadMysql() {
  if (kill(parent_pid, SIGUSR2)) {        // Did it fail?
    c3p_log(LOG_LEV_WARN, __PRETTY_FUNCTION__, "We failed to send a signal to pid %d, which we believe to be our parent process.", parent_pid);
    return 0;
  }
  db.db_connected = 0;     // Sending the signal will only benefit the children that fork later on. In order for our connection
  db.mysql = NULL;         // to be good, we need to re-establish it ourselves. Don't be too concerned about memory, as this PID will be reaped.
  return db.dbConnected();
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
  text_return->concatf("%s %s\n", program_name, PROGRAM_VERSION);
  return console.console_handler_help(text_return, args);
}

int callback_console_tools(StringBuilder* text_return, StringBuilder* args) {
  return console.console_handler_conf(text_return, args);
}

int callback_program_quit(StringBuilder* text_return, StringBuilder* args) {
  continue_running = false;
  text_return->concat("Stopping...\n");
  if (c3p_root_window) {
    c3p_root_window->closeWindow();
  }
  console.emitPrompt(false);  // Avoid a trailing prompt.
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
    max_field_print = args->position_as_int(0);
    if (max_field_print <= 0) {
      text_return->concatf("You tried to set the output width as 0. This is a bad idea. Setting the value to 64 instead.\n");
      max_field_print = 64;
    }
  }
  else {
    text_return->concatf("max-width is presently set to %d.\n", max_field_print);
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



/****************************************************************************************************
* Entry-point                                                                                       *
****************************************************************************************************/


int main(int argc, char *argv[]) {
  program_name            = argv[0];  // Our name.
  char *db_conf_filename  = NULL;     // Where should we look for our DB parameters?
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
      printf("%s v%s\n\n", argv[0], PROGRAM_VERSION);
      exit(0);
    }
    else if (strcasestr(argv[i], "--gui")) {
      // Instance an X11 window.
      c3p_root_window = new MainGuiWindow(0, 0, 1024, 768, "Librarian");
      if (c3p_root_window) {
        int8_t local_ret = c3p_root_window->map_button_inputs(mouse_buttons, sizeof(mouse_buttons) / sizeof(mouse_buttons[0]));
        c3p_log(LOG_LEV_ERROR, __PRETTY_FUNCTION__, "Defining buttons returns %d.", local_ret);
        if (0 == c3p_root_window->createWindow()) {
          // The window thread is running.
        }
        else {
          c3p_log(LOG_LEV_ERROR, __PRETTY_FUNCTION__, "Failed to instance the root GUI window.");
        }
      }
      else {
        c3p_log(LOG_LEV_ERROR, __PRETTY_FUNCTION__, "Failed to instance the root GUI window.");
      }
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
      c3p_log(LOG_LEV_ERROR, __PRETTY_FUNCTION__, "Failed to connect to database. Stopping...");
      //exit(1);
    }
    //conf.loadConfigFromDb(&db);         // Load config from the DB.
  }
  else {
    c3p_log(LOG_LEV_ERROR, __PRETTY_FUNCTION__, "Couldn't parse DB conf from %s. Stopping...", ((db_conf_filename == NULL) ? DEFAULT_CONF_FILE : db_conf_filename));
  }

  //// Alright... we are done loading configuration. Now let's make sure it is complete...
  //if (!conf.isConfigComplete()) {
  //    c3p_log(LOG_LEV_ERROR, __PRETTY_FUNCTION__, "Configuration is incomplete. Shutting down...");
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
        c3p_log(LOG_LEV_ERROR, __PRETTY_FUNCTION__, "%s was unable to read its own path from /proc/self/exe. You may be running it on an unsupported operating system, or be running an old kernel. Please discover the cause and retry. Exiting...", program_name);
        exit(1);
    }
    c3p_log(LOG_LEV_INFO, __PRETTY_FUNCTION__, "This binary's path is %s", exe_path);

    // Now to hash ourselves...
    char *h_buf = (char *)alloca(65);
    memset(h_buf, 0x00, 65);
    hashFileByPath(exe_path, h_buf);

    //// If we've stored a hash for our binary, compare it with the hash we calculated. Make sure they match. Pitch a fit if they don't.
    //if (conf.configKeyExists("binary-hash")) {
    //    if (strcasestr(h_buf, conf.getConfigStringByKey("binary-hash")) == NULL) {
    //      c3p_log(LOG_LEV_ERROR, __PRETTY_FUNCTION__, "Calculated hash value does not match what was stored in your config. Exiting...");
    //      exit(1);
    //    }
    //}
    ///* INTERNAL INTEGRITY-CHECKS */

  // We want to have a nice prompt string...
  StringBuilder prompt_string;
  //if (nullptr == c3p_root_window) {
    // If there is no GUI, mutually connect the console class to STDIO.
    console.localEcho(false);
    console_adapter.readCallback(&console);
    console.setOutputTarget(&console_adapter);
    console.hasColor(true);
    prompt_string.concatf("%c[36m%s> %c[39m", 0x1B, argv[0], 0x1B);
  //}
  //else {
  //  prompt_string.concatf("%s> ", argv[0]);
  //}
  console.setPromptString((const char*) prompt_string.string());
  console.emitPrompt(true);
  console.setTXTerminator(LineTerm::LF);
  console.setRXTerminator(LineTerm::LF);

  console.defineCommand("help",        '?',  "Prints help to console.", "[<specific command>]", 0, callback_help);
  console.defineCommand("console",     '\0', "Console conf.", "[echo|prompt|force|rxterm|txterm]", 0, callback_console_tools);
  console.defineCommand("pfinfo",      '\0', "Platform information", "[subgroup]", 0, callback_platform_info);
  console.defineCommand("info",        'i',  "Print the catalog's vital stats.", "", 0, callback_catalog_info);
  console.defineCommand("scan",        '\0', "Read the filesystem to fill out the catalog.", "", 0, callback_start_scan);
  console.defineCommand("unload",      '\0', "Discard the current catalog.", "", 0, callback_unload);
  console.defineCommand("max-print",   '\0', "Sets the maximum print width.", "", 0, callback_max_print_width);
  console.defineCommand("catalog",     '\0', "Create a new catalog at the given path.", "", 1, callback_new_catalog);
  console.defineCommand("tag",         '\0', "Set a tag for the catalog.", "", 1, callback_set_tag);
  console.defineCommand("notes",       '\0', "Set the notes on the catalog.", "", 1, callback_set_notes);
  console.defineCommand("quit",        'Q',  "Commit sudoku.", "", 0, callback_program_quit);
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

  console.emitPrompt(false);  // Avoid a trailing prompt.
  console_adapter.poll();

  delete c3p_root_window;   // Will block until the GUI thread is shut down.

  platform.firmware_shutdown(0);
  return 0;  // Should never execute.
}



/*******************************************************************************
* UI definition
*******************************************************************************/

// Create a simple console window, with a full frame.
GfxUITabbedContentPane _main_nav(
  GfxUILayout(
    0, 0,
    1024, 768,
    ELEMENT_MARGIN, ELEMENT_MARGIN, ELEMENT_MARGIN, ELEMENT_MARGIN,
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0xFFFFFF,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    2           // t_size
  ),
  0 //(GFXUI_FLAG_DRAW_FRAME_MASK)
);


GfxUIGroup _main_nav_catalogs(0, 0, 0, 0);
GfxUIGroup _main_nav_deltas(0, 0, 0, 0);
GfxUIGroup _main_nav_console(0, 0, 0, 0);
GfxUIGroup _main_nav_settings(0, 0, 0, 0);



GfxUITextButton _button_0(
  GfxUILayout(
    0, 0, 30, 30,
    0, ELEMENT_MARGIN, 0, ELEMENT_MARGIN,
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0x9932CC,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    1           // t_size
  ),
  "ST"
);

GfxUIButton _button_1(
  GfxUILayout(
    (_button_0.elementPosX() + _button_0.elementWidth() + 1), _button_0.elementPosY(),
    30, 30,
    0, ELEMENT_MARGIN, 0, ELEMENT_MARGIN,
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0x9932CC,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    1           // t_size
  )
);

GfxUITextButton _button_2(
  GfxUILayout(
    (_button_1.elementPosX() + _button_1.elementWidth() + 1), _button_1.elementPosY(),
    30, 30,
    0, ELEMENT_MARGIN, 0, ELEMENT_MARGIN,
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0xFF8C00,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    1           // t_size
  ),
  "Rm",
  (GFXUI_BUTTON_FLAG_MOMENTARY)
);

GfxUIButton _button_3(
  GfxUILayout(
    (_button_2.elementPosX() + _button_2.elementWidth() + 1), _button_2.elementPosY(),
    30, 30,
    0, ELEMENT_MARGIN, 0, ELEMENT_MARGIN,
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0xFF8C00,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    1           // t_size
  ),
  (GFXUI_BUTTON_FLAG_MOMENTARY)
);


GfxUISlider _slider_0(
  GfxUILayout(
    _button_0.elementPosX(), (_button_0.elementPosY() + _button_0.elementHeight() + 1),
    ((_button_3.elementPosX() + _button_3.elementWidth()) - _button_0.elementPosX()), 20,
    0, ELEMENT_MARGIN, 0, ELEMENT_MARGIN,
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0x20B2AA,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    1           // t_size
  ),
  (GFXUI_SLIDER_FLAG_RENDER_VALUE)
);

GfxUISlider _slider_1(
  GfxUILayout(
    _slider_0.elementPosX(), (_slider_0.elementPosY() + _slider_0.elementHeight() + 1),
    ((_button_3.elementPosX() + _button_3.elementWidth()) - _button_0.elementPosX()), 20,
    0, ELEMENT_MARGIN, 0, ELEMENT_MARGIN,
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0xFFA07A,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    1           // t_size
  ),
  (GFXUI_SLIDER_FLAG_RENDER_VALUE)
);

GfxUISlider _slider_2(
  GfxUILayout(
    _slider_1.elementPosX(), (_slider_1.elementPosY() + _slider_1.elementHeight() + 1),
    ((_button_3.elementPosX() + _button_3.elementWidth()) - _button_0.elementPosX()), 20,
    0, ELEMENT_MARGIN, 0, ELEMENT_MARGIN,
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0xFFA07A,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    1           // t_size
  ),
  (GFXUI_SLIDER_FLAG_RENDER_VALUE)
);

GfxUISlider _slider_3(
  GfxUILayout(
    _button_3.elementPosX() + _button_3.elementWidth(), (_button_3.elementPosY() + 1),
    24, ((_slider_2.elementPosY() + _slider_2.elementHeight()) - _button_0.elementPosY()),
    0, ELEMENT_MARGIN, 0, ELEMENT_MARGIN,
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0x90F5EE,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    1           // t_size
  ),
  (GFXUI_SLIDER_FLAG_RENDER_VALUE | GFXUI_SLIDER_FLAG_VERTICAL)
);

GfxUISlider _slider_4(
  GfxUILayout(
    (_slider_3.elementPosX() + _slider_3.elementWidth() + 1), (_slider_3.elementPosY() + 1),
    24, ((_slider_2.elementPosY() + _slider_2.elementHeight()) - _button_0.elementPosY()),
    0, ELEMENT_MARGIN, 0, ELEMENT_MARGIN,
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0xDC143C,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    1           // t_size
  ),
  (GFXUI_SLIDER_FLAG_RENDER_VALUE | GFXUI_SLIDER_FLAG_VERTICAL)
);


// Create a simple console window, with a full frame.
GfxUITextArea _txt_area_0(
  GfxUILayout(
    0, 0,
    400, 145,
    ELEMENT_MARGIN, ELEMENT_MARGIN, ELEMENT_MARGIN, ELEMENT_MARGIN,
    1, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0x00FF00,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    2           // t_size
  ),
  (GFXUI_FLAG_DRAW_FRAME_U)
);



// Create a text window, into which we will write running filter stats.
GfxUITextArea _program_info_txt(
  GfxUILayout(
    (_slider_4.elementPosX() + _slider_4.elementWidth() + 1), (_slider_4.elementPosY() + 1),
    500, 60,
    0, 0, 0, 0,
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0xC0C0C0,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    1           // t_size
  )
);


GfxUITimeSeriesDetail<uint32_t> data_examiner(
  GfxUILayout(
    0, 0,                    // Position(x, y)
    TEST_FILTER_DEPTH, 500,  // Size(w, h)
    ELEMENT_MARGIN, ELEMENT_MARGIN, ELEMENT_MARGIN, ELEMENT_MARGIN,  // Margins_px(t, b, l, r)
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(
    0,          // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0x40B0D0,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    2           // t_size
  ),
  &test_filter_0
);


// Create a text window, into which we will write running filter stats.
GfxUITextArea _filter_txt_0(
  GfxUILayout(
    data_examiner.elementPosX(), (data_examiner.elementPosY() + data_examiner.elementHeight()),
    data_examiner.elementWidth(), 120,
    0, ELEMENT_MARGIN, ELEMENT_MARGIN, ELEMENT_MARGIN,
    0, 0, 0, 0               // Border_px(t, b, l, r)
  ),
  GfxUIStyle(0, // bg
    0xFFFFFF,   // border
    0xFFFFFF,   // header
    0xC09030,   // active
    0xA0A0A0,   // inactive
    0xFFFFFF,   // selected
    0x202020,   // unselected
    2           // t_size
  )
);



void ui_value_change_callback(GfxUIElement* element) {
  if (element == ((GfxUIElement*) &_slider_1)) {
    c3p_log(LOG_LEV_INFO, __PRETTY_FUNCTION__, "Slider-1 %.2f", _slider_1.value());
  }
  else if (element == ((GfxUIElement*) &_slider_2)) {
    c3p_log(LOG_LEV_INFO, __PRETTY_FUNCTION__, "Slider-2 %.2f", _slider_2.value());
  }
  else if (element == ((GfxUIElement*) &_slider_3)) {
    c3p_log(LOG_LEV_INFO, __PRETTY_FUNCTION__, "Slider-3 %.2f", _slider_3.value());
  }
  else {
    c3p_log(LOG_LEV_INFO, __PRETTY_FUNCTION__, "VALUE_CHANGE %p", element);
  }
}




/*******************************************************************************
* TODO: Migrate to new source file, and promote to Linux Platform.
*******************************************************************************/

int8_t MainGuiWindow::createWindow() {
  int8_t ret = _init_window();
  if (0 == ret) {
    _overlay.reallocate();
    test_filter_0.init();
    test_filter_1.init();
    test_filter_stdev.init();

    _main_nav_settings.add_child(&_button_0);
    _main_nav_settings.add_child(&_button_1);
    _main_nav_settings.add_child(&_button_2);
    _main_nav_settings.add_child(&_button_3);
    _main_nav_settings.add_child(&_slider_0);
    _main_nav_settings.add_child(&_slider_1);
    _main_nav_settings.add_child(&_slider_2);
    _main_nav_settings.add_child(&_slider_3);
    _main_nav_settings.add_child(&_slider_4);
    _main_nav_settings.add_child(&_program_info_txt);

    _main_nav_catalogs.add_child(&data_examiner);
    _main_nav_catalogs.add_child(&_filter_txt_0);

    _main_nav_console.add_child(&_txt_area_0);

    // Adding the contant panes will cause the proper screen co-ords to be imparted
    //   to the group objects. We can then use them for element flow.
    _main_nav.addTab("Catalogs", &_main_nav_catalogs, true);
    _main_nav.addTab("Deltas", &_main_nav_deltas);
    _main_nav.addTab("Console", &_main_nav_console);
    _main_nav.addTab("Settings", &_main_nav_settings);

    root.add_child(&_main_nav);

    const uint  CONSOLE_INPUT_X_POS = _main_nav_console.elementPosX();
    const uint  CONSOLE_INPUT_Y_POS = (height() - CONSOLE_INPUT_HEIGHT) - 1;
    _txt_area_0.reposition(CONSOLE_INPUT_X_POS, CONSOLE_INPUT_Y_POS);
    _txt_area_0.resize(width(), CONSOLE_INPUT_HEIGHT);

    console.setOutputTarget(&_txt_area_0);
    console.hasColor(false);
    console.localEcho(true);

    _filter_txt_0.enableFrames(GFXUI_FLAG_DRAW_FRAME_U);

    _slider_0.value(0.5);
    _refresh_period.reset();
    setCallback(ui_value_change_callback);
  }
  return ret;
}



int8_t MainGuiWindow::closeWindow() {
  continue_running = false;
  return _deinit_window();
}



int8_t MainGuiWindow::render_overlay() {
  return 0;
}


/*
* Called to unconditionally show the elements in the GUI.
*/
int8_t MainGuiWindow::render(bool force) {
  int8_t ret = 0;
  if (force) {
    StringBuilder pitxt;
    pitxt.concat("Build date " __DATE__ " " __TIME__);
    struct utsname sname;
    if (1 != uname(&sname)) {
      pitxt.concatf("%s %s (%s)", sname.sysname, sname.release, sname.machine);
      pitxt.concatf("\n%s", sname.version);
    }
    pitxt.concatf("Window: %dx%d", _fb.x(), _fb.y());
    _program_info_txt.clear();
    _program_info_txt.provideBuffer(&pitxt);
  }
  return ret;
}



// Called from the thread.
int8_t MainGuiWindow::poll() {
  int8_t ret = 0;
  while (0 < XPending(_dpy)) {
    Atom WM_DELETE_WINDOW = XInternAtom(_dpy, "WM_DELETE_WINDOW", False);
    XEvent e;
    XNextEvent(_dpy, &e);

    switch (e.type) {
      case Expose:
        {
          int8_t local_ret = _refit_window();
          if (0 != local_ret) {
            c3p_log(LOG_LEV_ERROR, __PRETTY_FUNCTION__, "Window resize failed (%d).", local_ret);
          }
        }
        break;

      case ButtonPress:
      case ButtonRelease:
        {
          int8_t ret = _proc_mouse_button(e.xbutton.button, e.xbutton.x, e.xbutton.y, (e.type == ButtonPress));
          if (0 == ret) {
            // Any unclaimed input can be handled in this block.
          }
        }
        break;

      case KeyPress:
        {
          char buf[128] = {0, };
          KeySym keysym;
          int ret_local = XLookupString(&e.xkey, buf, sizeof(buf), &keysym, nullptr);
          if (keysym == XK_Escape) {
            _keep_polling = false;
          }
          else if (keysym == XK_Return) {
            StringBuilder _tmp_sbldr;
            _tmp_sbldr.concat('\n');
            console.provideBuffer(&_tmp_sbldr);
          }
          else if (1 == ret_local) {
            StringBuilder _tmp_sbldr;
            _tmp_sbldr.concat(buf[0]);
            console.provideBuffer(&_tmp_sbldr);
          }
          else {
            c3p_log(LOG_LEV_DEBUG, __PRETTY_FUNCTION__, "Key press: %s (%s)", buf, XKeysymToString(keysym));
          }
        }
        break;


      case ClientMessage:
        if (static_cast<unsigned int>(e.xclient.data.l[0]) == WM_DELETE_WINDOW) {
          _keep_polling = false;
        }
        break;

      case MotionNotify:
        _pointer_x = e.xmotion.x;
        _pointer_y = e.xmotion.y;
        _process_motion();
        break;

      default:
        c3p_log(LOG_LEV_DEBUG, __PRETTY_FUNCTION__, "Unhandled XEvent: %d", e.type);
        break;
    }
  }

  if (!_keep_polling) {
    closeWindow();
    ret = -1;
  }
  else {
    // Render the UI elements...
    // TODO: Should be in the relvant class.
    if (test_filter_0.dirty()) {
      StringBuilder _tmp_sbldr;
      _tmp_sbldr.concatf("RMS:      %.2f\n", (double) test_filter_0.rms());
      _tmp_sbldr.concatf("STDEV:    %.2f\n", (double) test_filter_0.stdev());
      _tmp_sbldr.concatf("SNR:      %.2f\n", (double) test_filter_0.snr());
      _tmp_sbldr.concatf("Min/Max:  %.2f / %.2f\n", (double) test_filter_0.minValue(), (double) test_filter_0.maxValue());
      _filter_txt_0.clear();
      _filter_txt_0.provideBuffer(&_tmp_sbldr);
    }
    if (1 == _redraw_window()) {
      if (1 == test_filter_0.feedFilter(_redraw_timer.lastTime())) {
        test_filter_stdev.feedFilter(test_filter_0.stdev());
      }
    }
  }

  return ret;
}
