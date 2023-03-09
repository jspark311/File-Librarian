################################################################################
# Makefile for librarian
# Author: J. Ian Lindsay
#
################################################################################

CC		= g++
CXXFLAGS = -I./src -I./lib/CppPotpourri/src -I./lib/Platform -Wl,--gc-sections -fsingle-precision-constant -fno-rtti -fno-exceptions -Wall

# Libraries to link against.
LIBS	= -L$(OUTPUT_PATH) -L$(BUILD_ROOT)/lib -lstdc++ -lX11 -lcrypto -lm $(shell mysql_config --libs)

export BUILD_ROOT    = $(shell pwd)
export OUTPUT_PATH   = $(BUILD_ROOT)/build/

###########################################################################
# Source files, includes, and linker directives...
###########################################################################

SRCS    = src/librarian.cpp src/MySQLConnector/*.cpp
SRCS   += src/ConfigManager/*.cpp src/MySQLConnector/DBAbstractions/*.cpp
SRCS   += lib/CppPotpourri/src/*.cpp
SRCS   += lib/CppPotpourri/src/Image/*.cpp
SRCS   += lib/CppPotpourri/src/Image/ImageUtils/*.cpp
SRCS   += lib/CppPotpourri/src/Image/GfxUI/*.cpp
SRCS   += lib/CppPotpourri/src/Identity/*.cpp
SRCS   += lib/CppPotpourri/src/CryptoBurrito/*.cpp
SRCS   += lib/CppPotpourri/src/CryptoBurrito/Providers/*.cpp
SRCS   += lib/CppPotpourri/src/cbor-cpp/*.cpp
SRCS   += lib/Platform/src/Linux.cpp
SRCS   += lib/Platform/src/LinuxStdIO.cpp
SRCS   += lib/Platform/src/GUI/X11/*.cpp



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

fullclean: clean
	$(MAKE) clean -C lib/
