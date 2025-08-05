ifneq ($(words $(MAKECMDGOALS)),1) # if no argument was given to make...
.DEFAULT_GOAL = ceccomp # set the default goal to all
%:                   # define a last resort default rule
	@$(MAKE) $@ --no-print-directory -rRf $(firstword $(MAKEFILE_LIST)) # recursive make call, 
else
	ifndef ECHO
	T := $(shell $(MAKE) $(MAKECMDGOALS) --no-print-directory \
		-nrRf $(firstword $(MAKEFILE_LIST)) \
		ECHO="COUNTTHIS" | grep -c "COUNTTHIS")
	L := $(shell echo -n $T | wc -m)
	GREEN := $(shell printf '\033[32m')
	RESET := $(shell printf '\033[0m')
	ECHO_NOPROG = printf "    $(1)\t$(2)\n"
	ECHO = printf "    $(1)\t[%$Ld/%$Ld]\t$(2)\n" \
		$(shell flock $(LOCK) -c 'read n < $(MARK); echo $$n; echo $$((n+1)) > $(MARK)') \
		$T
	endif

TARGET := ceccomp test

SRC_DIR := src
INC_DIR := include
TEST_DIR := test
BUILD_DIR := build
BUILD_UTIL := $(BUILD_DIR)/utils

LOCK := $(BUILD_DIR)/lock
MARK := $(BUILD_DIR)/progress

C_SRCS := $(shell find $(SRC_DIR) ! -name 'ceccomp.c' -name '*.c' -or -name '*.s')
TEST_SRCS := $(shell find $(TEST_DIR) -name '*.c')

OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.c.o,$(C_SRCS))
TEST_OBJS := $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/%.c.o,$(TEST_SRCS))

CECCOMP_MAIN := $(BUILD_DIR)/ceccomp.c.o

CC := gcc

CFLAGS := -fpie -fstack-protector -Wall -Wextra
LDFLAGS := -z now -z noexecstack -fpie -fstack-protector -Wall -Wextra -lseccomp

ifdef DEBUG
	ifeq ($(DEBUG),1)
		CFLAGS += -g -O2
		LDFLAGS += -g -O2
	else ifeq ($(DEBUG),2)
		CFLAGS += -g
		LDFLAGS += -g
	endif
else
	CFLAGS += -O2
	LDFLAGS += -O2
endif

DEST_DIR ?= 
PREFIX ?= $(DEST_DIR)/usr
BIN_DIR ?= $(PREFIX)/bin
ZSH_DST ?= $(PREFIX)/share/zsh/site-functions
ZSH_SRC := completions

all: ceccomp test check

install: bin_install zsh_cmp_install

bin_install: $(BUILD_DIR)/ceccomp
	@$(call ECHO_NOPROG,MKDIR,$(BIN_DIR))
	@mkdir -p $(BIN_DIR)
	@$(call ECHO_NOPROG,INSTALL,$< $(BIN_DIR))
	@install $< $(BIN_DIR)

zsh_cmp_install: $(ZSH_SRC)/_ceccomp
	@$(call ECHO_NOPROG,MKDIR,$(ZSH_DST))
	@mkdir -p $(ZSH_DST)
	@$(call ECHO_NOPROG,INSTALL,$< $(ZSH_DST))
	@install -m 0644 $< $(ZSH_DST)

ceccomp: init_progress $(BUILD_DIR)/ceccomp
	@$(call ECHO_NOPROG,$(GREEN)BUILT,$@$(RESET))

$(BUILD_DIR)/ceccomp: $(OBJS) $(CECCOMP_MAIN)
	@$(call ECHO,LD,$@)
	@$(CC) $(LDFLAGS) $^ -o $@

test: init_progress $(BUILD_DIR)/test
	@$(call ECHO_NOPROG,$(GREEN)BUILT,$@$(RESET))

$(BUILD_DIR)/test: $(TEST_OBJS)
	@$(call ECHO,LD,$@)
	@$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/%.c.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@$(call ECHO,CC,$@)
	@$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@
$(BUILD_DIR)/%.c.o: $(TEST_DIR)/%.c | $(BUILD_DIR)
	@$(call ECHO,CC,$@)
	@$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@

$(BUILD_DIR):
	@$(call ECHO_NOPROG,MKDIR,$(BUILD_DIR))
	@mkdir -p $(BUILD_DIR) $(BUILD_UTIL) $(BUILD_TEST)

init_progress: | $(BUILD_DIR)
	@echo 1 > $(MARK)

.PHONY: clean all check check_disasm check_asm check_emu init_progress ceccomp test
clean:
	@$(call ECHO_NOPROG,RM,$(BUILD_DIR))
	@rm -rf $(BUILD_DIR)

endif
