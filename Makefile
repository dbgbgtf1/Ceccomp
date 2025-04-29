TARGET = Test Ceccomp

CC := gcc
CXX := g++

CFLAGS := -lseccomp

BUILD_DIR := ./build
BUILD_UTILS_DIR = ./build/utils

SRC_DIR := ./src
INC_DIRS := ./include/

SRCS := ./src/asm.c ./src/disasm.c ./src/dump.c ./src/emu.c ./src/utils/parsefilter.cpp ./src/utils/parseobj.c ./src/utils/preasm.c ./src/utils/transfer.c

C_SRCS := $(filter %.c, $(SRCS))
CPP_SRCS := $(filter %.cpp, $(SRCS))

C_OBJS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.c.o, $(C_SRCS))
CPP_OBJS := $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.cpp.o, $(CPP_SRCS))

OBJS := $(C_OBJS) $(CPP_OBJS)
CECCOMP_MAIN := $(BUILD_DIR)/main.c.o
TEST_MAIN := $(BUILD_DIR)/test.c.o

ceccomp: $(OBJS) $(CECCOMP_MAIN)
	$(CXX) $(CFLAGS) $^ -g -o $@

test: $(OBJS) $(TEST_MAIN)
	$(CXX) $(CFLAGS) $^ -g -o $@

$(BUILD_DIR)/%.c.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) -I$(INC_DIRS) -c $< -g -o $@

$(BUILD_DIR)/%.cpp.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) -I$(INC_DIRS) $(CXXFLAGS) -c $< -g -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR) $(BUILD_UTILS_DIR)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) Ceccomp Test
