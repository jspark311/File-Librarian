###########################################################################
# Makefile for libraries
# Author: J. Ian Lindsay
###########################################################################

LIBS_TO_BUILD  = cpppotpourri.a platform.a mbedtls.a


###########################################################################
# Parameter unification and make targets
###########################################################################

.PHONY: all

all: $(LIBS_TO_BUILD)
	@echo "\033[1;37m$(LIBS_TO_BUILD)\033[0m"

mbedtls.a:
	@echo "\033[1;37m=== mbedtls ==========================================\033[0m"
	$(MAKE) lib -C mbedtls/
	cp -RP mbedtls/library/*.a $(OUTPUT_PATH)

cpppotpourri.a:

platform.a:

clean:
	$(MAKE) clean -C CppPotpourri
	$(MAKE) clean -C Platform
	$(MAKE) clean -C mbedtls
