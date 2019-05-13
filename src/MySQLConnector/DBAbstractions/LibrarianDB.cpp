#include "ORM.h"
#include "DataStructures/StringBuilder.h"
#include <stdio.h>
#include <syslog.h>

extern void fp_log(const char *fxn_name, int severity, const char *message, ...);

LibrarianDB* INSTNACE = nullptr;


LibrarianDB* LibrarianDB::getInstance() {
	return INSTNACE;
}



/* Constructor. Builds the MySQLConnector. */
LibrarianDB::LibrarianDB(void) : MySQLConnector() {
	INSTNACE = this;
}

LibrarianDB::~LibrarianDB(void) {
}
