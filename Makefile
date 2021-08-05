.PHONY: docs clean

TEST_PROJECT=run_tests

#=========== DIRS ===========#

VPATH += lib/
VPATH += docs/
VPATH += helpers/
VPATH += includes/
VPATH += src/
VPATH += tests/

#=========== TOOLS ===========#

CC ?= gcc
LD ?= gcc

#=========== FLAGS ===========#

LDFLAGS ?= -w -g
CFLAGS ?= -w -g
LDLIBS	?= -lcrypto -lssl

DEFINES ?= DEBUG

#=========== INCLUDE ===========#

include lib/Makefile.include
include Makefile.include

#=========== INCLUDE ===========#

OBJS = $(addprefix bin/, $(SRCS:.c=.o))



#=========== COMMANDS ===========#

all: $(TEST_PROJECT)

$(TEST_PROJECT): $(OBJS)
	@gcc $(LDFLAGS) $(OBJS) -o $@ $(LDLIBS)
	@echo "Compilation done!"

bin/%.o : %.c
	@mkdir -p $(dir $@)
	@gcc $(CFLAGS) $(addprefix -D, $(DEFINES)) $(addprefix -I, $(INCLUDES)) -c $< -o $@
	@echo cc -c $< -o $@

clean:
	rm -rf bin/
	rm -f $(TEST_PROJECT)

docs:
	doxygen dox/doxygen.cfg
