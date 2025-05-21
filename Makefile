TARGET := ceccomp test

SRC_DIR := ./src
INC_DIR := ./include
TEST_DIR := ./test
BUILD_DIR := ./build
BUILD_UTIL := ./build/utils

C_SRCS := $(shell find $(SRC_DIR) ! -name 'ceccomp.c' -name '*.c' -or -name '*.s')
CXX_SRCS := $(shell find $(SRC_DIR) -name '*.cpp')
TEST_SRCS := $(shell find $(TEST_DIR) -name '*.c')

C_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.c.o,$(C_SRCS))
CXX_OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.cpp.o,$(CXX_SRCS))
TEST_OBJS := $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/%.c.o,$(TEST_SRCS))
OBJS := $(C_OBJS) $(CXX_OBJS)

CECCOMP_MAIN := $(BUILD_DIR)/ceccomp.c.o

CC := gcc
CXX := g++

CFLAGS := -fpie -fstack-protector -Wall -Wextra
CXXFLAGS := -fpie -fstack-protector -Wall -Wextra
LDFLAGS := -lseccomp -z now -z noexecstack -fpie -fstack-protector -Wall -Wextra

ifdef DEBUG
	ifeq ($(DEBUG),1)
		CFLAGS += -g -O2
		CXXFLAGS += -g -O2
		LDFLAGS += -g -O2
	else ifeq ($(DEBUG),2)
		CFLAGS += -g
		CXXFLAGS += -g 
		LDFLAGS += -g
	endif
else
	CFLAGS += -O2
	CXXFLAGS += -O2
	LDFLAGS += -O2
endif

DEST_DIR ?= 
PREFIX ?= $(DEST_DIR)/usr
BIN_DIR ?= $(PREFIX)/bin
ZSH_DST ?= $(PREFIX)/share/zsh/site-functions
ZSH_SRC := ./completions

all: ceccomp test

install: bin_install zsh_cmp_install
	@echo "install success"

bin_install: ceccomp
	mkdir -p $(BIN_DIR)
	cp $(BUILD_DIR)/$< $(BIN_DIR)/$<

zsh_cmp_install: $(ZSH_SRC)/_ceccomp
	mkdir -p $(ZSH_DST)
	cp $< $(ZSH_DST)/_ceccomp

ceccomp: $(OBJS) $(CECCOMP_MAIN)
	$(CXX) $(LDFLAGS) $^ -o $@
	mv -f $@ $(BUILD_DIR)
	@echo "ceccomp is maked"
	@echo ""

test: $(TEST_OBJS)
	$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)/$@
	@echo "test is maked"
	@echo ""

$(BUILD_DIR)/%.c.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@
$(BUILD_DIR)/%.cpp.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) -I$(INC_DIR) $(CXXFLAGS) $< -c -o $@
$(BUILD_DIR)/%.c.o: $(TEST_DIR)/%.c | $(BUILD_DIR)
	$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR) $(BUILD_UTIL) $(BUILD_TEST)

.PHONY: clean all
clean:
	rm -rf $(BUILD_DIR)
