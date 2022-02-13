#include "ORM.h"
#include "StringBuilder.h"
#include <stdio.h>
#include <syslog.h>

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
