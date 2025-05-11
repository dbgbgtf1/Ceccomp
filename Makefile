TARGET := ceccomp test

SRC_DIR := ./src
INC_DIR := ./include
BUILD_DIR := ./build
BUILD_UTIL := ./build/utils

C_SRCS := $(shell find ./src ! -name 'ceccomp.c' ! -name 'test.c' -name '*.c' -or -name '*.s')
CXX_SRCS := $(shell find $(SRC_DIR) -name '*.cpp')

C_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.c.o,$(C_SRCS))
CXX_OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.cpp.o,$(CXX_SRCS))
OBJS := $(C_OBJS) $(CXX_OBJS)

CECCOMP_MAIN := $(BUILD_DIR)/ceccomp.c.o
TEST_MAIN := $(BUILD_DIR)/test.c.o

CC := gcc
CXX := g++

CFLAGS := 
CXXFLAGS := 
LDFLAGS := -lseccomp

ifdef DEBUG
	ifeq ($(DEBUG),1)
		CFLAGS += -g -O3
		CXXFLAGS += -g -O3
		LDFLAGS += -g -O3
	else ifeq ($(DEBUG),2)
		CFLAGS += -g
		CXXFLAGS += -g 
		LDFLAGS += -g
	endif
else
	CFLAGS += -O3
	CXXFLAGS += -O3
	LDFLAGS += -O3
endif

DEST_DIR ?= 
PREFIX ?= $(DEST_DIR)/usr
BIN_DIR ?= $(PREFIX)/bin
ZSH_DST ?= $(PREFIX)/share/zsh/site-functions
ZSH_SRC := ./completions

all: $(BUILD_DIR)/ceccomp

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

test: $(OBJS) $(TEST_MAIN)
	echo $(C_SRCS)
	$(CXX) $(LDFLAGS) $^ -o $@
	mv $@ $(BUILD_DIR)

$(BUILD_DIR)/%.c.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@
$(BUILD_DIR)/%.cpp.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) -I$(INC_DIR) $(CXXFLAGS) $< -c -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR) $(BUILD_UTIL)

.PHONY: clean all
clean:
	rm -rf $(BUILD_DIR)
