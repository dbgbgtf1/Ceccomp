TARGET = Test Ceccomp

CC := gcc
CXX := g++

CFLAGS := -lseccomp
# CXXFLAGS := -DDEBUG

BUILD_DIR := ./build
SRC_DIR := ./src
INC_DIRS := ./include/

SRCS := ./src/Dump.c ./src/Disasm.c ./src/parsefilter.cpp ./src/Emu.c ./src/transfer.c ./src/preasm.c ./src/parseobj.c
C_SRCS := $(filter %.c, $(SRCS))
CPP_SRCS := $(filter %.cpp, $(SRCS))

C_OBJS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.c.o, $(C_SRCS))
CPP_OBJS := $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.cpp.o, $(CPP_SRCS))

OBJS := $(C_OBJS) $(CPP_OBJS)
CECCOMP_MAIN := $(BUILD_DIR)/Main.c.o
TEST_MAIN := $(BUILD_DIR)/test.c.o

Ceccomp: $(OBJS) $(CECCOMP_MAIN)
	$(CXX) $(CFLAGS) $^ -g -o $@

Test: $(OBJS) $(TEST_MAIN)
	$(CXX) $(CFLAGS) $^ -g -o $@

$(BUILD_DIR)/%.c.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) -I$(INC_DIRS) -c $< -g -o $@

$(BUILD_DIR)/%.cpp.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) -I$(INC_DIRS) $(CXXFLAGS) -c $< -g -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) Ceccomp Test
