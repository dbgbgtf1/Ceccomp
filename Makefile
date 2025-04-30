TARGET := ceccomp test

SRC_DIR := ./src
INC_DIR := ./include
BUILD_DIR := ./build
BUILD_UTIL := ./build/utils

C_SRCS := $(shell find $(SRC_DIR) -name '*.c' -or -name '*.s' ! -name 'ceccomp.c' ! -name 'test.c')
CXX_SRCS := $(shell find $(SRC_DIR) -name '*.cpp')

C_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.c.o,$(C_SRCS))
CXX_OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.cpp.o,$(CXX_SRCS))
OBJS := $(C_OBJS) $(CXX_OBJS)

CECCOMP_MAIN := $(BUILD_DIR)/ceccomp.c.o
TEST_MAIN := $(BUILD_DIR)/test.c.o

CC := gcc
CXX := g++

CFLAGS := -lseccomp
CXXFLAGS := -lseccomp

ifdef DEBUG
	CFLAGS += -g
	CXXFLAGS += -g
else
	CFLAGS += -O3
	CXXFLAGS += -O3
endif

$(BUILD_DIR)/ceccomp: $(OBJS) $(CECCOMP_MAIN)
	$(CXX) $(CXXFLAGS) $^ -o $@

$(BUILD_DIR)/%.c.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@
$(BUILD_DIR)/%.cpp.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) -I$(INC_DIR) $(CXXFLAGS) $< -c -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR) $(BUILD_UTIL)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
