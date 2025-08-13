ifneq ($(words $(MAKECMDGOALS)),1) # if no argument was given to make...
.DEFAULT_GOAL = all
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
		$(shell SHELL=$(SHELL) flock $(LOCK) -c 'read n < $(MARK); echo $$n; echo $$((n+1)) > $(MARK)') \
		$T
	endif

VERSION := 2.9
ifneq ($(findstring .,$(VERSION)),)
	TAG := v$(VERSION)
else
	TAG := $(VERSION)
endif
TAG_TIME := $(shell git log -1 --format=format:%as $(TAG))
ARCH := $(shell uname -m)

TARGET := ceccomp test

SRC_DIR := src
INC_DIR := include
TEST_DIR := test
DOC_DIR := docs
IMG_DIR := images
SRC_IMG_DIR := $(DOC_DIR)/$(IMG_DIR)
BUILD_DIR := build
BUILD_IMG_DIR := $(BUILD_DIR)/$(IMG_DIR)
BUILD_UTIL := $(BUILD_DIR)/utils

LOCK := $(BUILD_DIR)/lock
MARK := $(BUILD_DIR)/progress

C_SRCS := $(shell find $(SRC_DIR) ! -name 'ceccomp.c' -name '*.c' -or -name '*.s')
TEST_SRCS := $(shell find $(TEST_DIR) -name '*.c')
IMG_SRCS := $(shell find $(SRC_IMG_DIR) -name "*.png")

OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.c.o,$(C_SRCS))
TEST_OBJS := $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/%.c.o,$(TEST_SRCS))
IMG_OBJS := $(patsubst $(SRC_IMG_DIR)/%.png,$(BUILD_IMG_DIR)/%.png,$(IMG_SRCS))

CECCOMP_MAIN := $(BUILD_DIR)/ceccomp.c.o

CC := gcc

CFLAGS := -fpie -fstack-protector -Wall -Wextra '-DVERSION_CODE="$(VERSION)"'
LDFLAGS := -z now -z noexecstack -fpie -fstack-protector -Wall -Wextra -lseccomp

ifdef DEBUG
	ifeq ($(DEBUG),1)
		CFLAGS += -g -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer
		LDFLAGS += -g -O2
	else ifeq ($(DEBUG),2)
		CFLAGS += -g3 -O0 -DDEBUG # O0 preserve fp by default
		LDFLAGS += -g3 -O0
	endif
else
	CFLAGS += -O2
	LDFLAGS += -O2 -s
endif

DEST_DIR ?= 
PREFIX ?= $(DEST_DIR)/usr
BIN_DIR ?= $(PREFIX)/bin
ZSH_DST ?= $(PREFIX)/share/zsh/site-functions
ZSH_SRC := completions

all: ceccomp doc

doc: doc_html doc_man

doc_man: init_progress $(BUILD_DIR)/ceccomp.1
	@$(call ECHO_NOPROG,$(GREEN)BUILT,man doc$(RESET))

doc_html: init_progress $(IMG_OBJS) $(BUILD_DIR)/index.html
	@$(call ECHO_NOPROG,$(GREEN)BUILT,html doc$(RESET))

$(BUILD_DIR)/ceccomp.1: $(DOC_DIR)/ceccomp.adoc
	@$(call ECHO,ASCIIDOC,$@)
	@asciidoctor -b manpage $< -a VERSION=$(VERSION) -a ARCH=$(ARCH) -a TAG_TIME=$(TAG_TIME) -o $@

$(BUILD_DIR)/index.html: $(DOC_DIR)/ceccomp.adoc
	@$(call ECHO,ASCIIDOC,$@)
	@asciidoctor -b html5 $< -a VERSION=$(VERSION) -a ARCH=$(ARCH) -a TAG_TIME=$(TAG_TIME) -o $@

$(BUILD_IMG_DIR)/%.png: $(SRC_IMG_DIR)/%.png
	@$(call ECHO_NOPROG,CP,$(notdir $<))
	@cp $< $@

install: bin_install zsh_cmp_install

bin_install: $(BUILD_DIR)/ceccomp
	@$(call ECHO_NOPROG,INSTALL,$< $(BIN_DIR))
	@install -Dt $(BIN_DIR) $<

zsh_cmp_install: $(ZSH_SRC)/_ceccomp
	@$(call ECHO_NOPROG,INSTALL,$< $(ZSH_DST))
	@install -Dm 0644 -t $(ZSH_DST) $<

ceccomp: init_progress $(BUILD_DIR)/ceccomp
	@$(call ECHO_NOPROG,$(GREEN)BUILT,$@$(RESET))

$(BUILD_DIR)/ceccomp: $(OBJS) $(CECCOMP_MAIN)
	@$(call ECHO,LD,$@)
	@$(CC) $(LDFLAGS) $^ -o $@

test: init_progress $(BUILD_DIR)/test
	@$(call ECHO_NOPROG,$(GREEN)BUILT,$@$(RESET))

$(BUILD_DIR)/test: $(TEST_OBJS)
	@$(call ECHO,LD,$@)
	@$(CC) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/%.c.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@$(call ECHO,CC,$@)
	@$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@
$(BUILD_DIR)/%.c.o: $(TEST_DIR)/%.c | $(BUILD_DIR)
	@$(call ECHO,CC,$@)
	@$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@

$(BUILD_DIR):
	@$(call ECHO_NOPROG,MKDIR,$(BUILD_DIR))
	@mkdir -p $(BUILD_DIR) $(BUILD_UTIL) $(BUILD_TEST) $(BUILD_IMG_DIR)

init_progress: | $(BUILD_DIR)
	@echo 1 > $(MARK)

.PHONY: clean all init_progress ceccomp test doc doc_html doc_man
clean:
	@$(call ECHO_NOPROG,RM,$(BUILD_DIR))
	@rm -rf $(BUILD_DIR)

endif
