.PHONY: docs clean menuconfig tests shared static

PROJECT:=mbedcrypto

KCONFIG_CONFIG:=mbcrypt.config

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
#VPATH += arch/

#=========== INCLUDES ===========#

ifneq ("$(wildcard $(KCONFIG_CONFIG))","")
include $(KCONFIG_CONFIG)
else
$(info $(KCONFIG_CONFIG) not found! Use < make menuconfig > to configure the library)
endif


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

debug:
	@${MAKE} $(PROJECT)_tests BUILD_TYPE=EXECUTABLE CONFIG_BUILD_MODE_DEBUG=y

cicd: 
	@${MAKE} $(PROJECT)_tests BUILD_TYPE=EXECUTABLE_TESTS 

clean:
	@rm -rf bin/
	@rm -f $(PROJECT)_shared
	@rm -f $(PROJECT)_static
	@rm -f $(PROJECT)_tests

docs:
	@doxygen docs/doxygen.cfg

menuconfig:
	@kconfig-mconf KConfig

config:
	@kconfig-conf KConfig

def-config:
	@ echo def_$(KCONFIG_CONFIG) > $(KCONFIG_CONFIG)

-include Makefile.build
