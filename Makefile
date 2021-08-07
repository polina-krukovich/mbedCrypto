.PHONY: docs clean menuconfig tests shared static

PROJECT=mbedcrypto

KCONFIG_CONFIG=mbcrypt.config

#=========== TOOLS ===========#

CC ?= gcc
LD ?= gcc

#=========== DIRS ===========#
VPATH += lib/
VPATH += docs/
VPATH += helpers/
VPATH += includes/
VPATH += src/
VPATH += tests/

#=========== INCLUDES ===========#

include mbcrypt.config

include lib/Makefile.include
include Makefile.include


#=========== COMMANDS ===========#

all: tests

shared:
	@${MAKE} $(PROJECT)_shared BUILD_TYPE=SHARED

static:
	@${MAKE} $(PROJECT)_static BUILD_TYPE=STATIC

tests: 
	@${MAKE} $(PROJECT)_tests BUILD_TYPE=EXECUTABLE


clean:
	@rm -rf bin/
	@rm -f $(PROJECT)_shared
	@rm -f $(PROJECT)_static
	@rm -f $(PROJECT)_tests

docs:
	@doxygen docs/doxygen.cfg

menuconfig:
	@kconfig-mconf KConfig


-include Makefile.build
