# Makefile for librarian.
# Author: J. Ian Lindsay

CC		= g++
CXXFLAGS = -I./src -I./lib/CppPotpourri/src -Wl,--gc-sections -static -Wall
LIBS	= -L$(OUTPUT_PATH) -L$(BUILD_ROOT)/lib -lstdc++ -lcrypto -lm $(shell mysql_config --libs)

export BUILD_ROOT    = $(shell pwd)
export OUTPUT_PATH   = $(BUILD_ROOT)/build/

SRCS    = src/librarian.cpp src/MySQLConnector/*.cpp
SRCS   += lib/CppPotpourri/src/*.cpp
SRCS   += lib/Platform/src/Linux.cpp
SRCS   += src/ConfigManager/*.cpp src/MySQLConnector/DBAbstractions/*.cpp

default:	librarian

builddir:
	mkdir -p $(OUTPUT_PATH)

debug:  librarian.o
	$(CC) $(CXXFLAGS) -ggdb -g -pg -o librarian *.o $(LIBS)

librarian:	librarian.o
	$(CC) $(CXXFLAGS) -o librarian *.o $(LIBS)

librarian.o:
	$(CC) $(CXXFLAGS) $(CFLAGS) -c $(SRCS) -fno-exceptions

install:	librarian
	cp librarian /usr/bin/librarian

clean:
	rm -rf $(OUTPUT_PATH)
	rm -f librarian *.o *~
