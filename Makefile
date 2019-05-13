# Makefile for librarian.
# Author: J. Ian Lindsay

CC		= gcc
CFLAGS	= -Wall
CXXFLAGS = -I./src -D__MANUVR_LINUX
LIBS	= -L$(OUTPUT_PATH) -L$(BUILD_ROOT)/lib -lstdc++ -lcrypto -lm $(shell mysql_config --libs)

export BUILD_ROOT    = $(shell pwd)
export OUTPUT_PATH   = $(BUILD_ROOT)/build/


SRCS    = src/librarian.cpp src/MySQLConnector/*.cpp src/DataStructures/*.cpp
SRCS   += src/ConfigManager/*.cpp src/MySQLConnector/DBAbstractions/*.cpp

default:	librarian

builddir:
	mkdir -p $(OUTPUT_PATH)

debug:  librarian.o
	$(CC) $(CFLAGS) -ggdb -g -pg -o librarian *.o $(LIBS)

librarian:	librarian.o
	$(CC) $(CFLAGS) -o librarian *.o $(LIBS)

librarian.o:
	$(CC) $(CXXFLAGS) $(CFLAGS) -c $(SRCS) -fno-exceptions

install:	librarian
	cp librarian /usr/bin/librarian

clean:
	rm -rf $(OUTPUT_PATH)
	rm -f librarian *.o *~
