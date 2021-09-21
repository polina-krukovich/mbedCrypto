.PHONY: docs clean menuconfig tests shared static

BUILD_MAKEFILE := Makefile.build

all: tests

shared:
	@${MAKE} -f $(BUILD_MAKEFILE) BUILD_TYPE=SHARED

static:
	@${MAKE} -f $(BUILD_MAKEFILE) BUILD_TYPE=STATIC

tests: 
	@${MAKE} -f $(BUILD_MAKEFILE) BUILD_TYPE=EXECUTABLE

debug:
	@${MAKE} -f $(BUILD_MAKEFILE) BUILD_TYPE=EXECUTABLE CONFIG_BUILD_MODE_DEBUG=y

cicd: 
	@${MAKE} -f $(BUILD_MAKEFILE) BUILD_TYPE=EXECUTABLE KCONFIG_CONFIG=test.config

clean:
	@rm -rf bin/
	@rm -rf build/

docs:
	@doxygen docs/doxygen.cfg

menuconfig:
	@kconfig-mconf KConfig

config:
	@kconfig-conf KConfig