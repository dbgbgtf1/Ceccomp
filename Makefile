CC := gcc
CXX := g++
CFLAGS := -lseccomp
# CXXFLAGS := -DDEBUG
BUILD_DIR := ./build
SRC_DIR := ./src

SRCS := ./src/parsefilter.cpp ./src/tools_test.c ./src/transfer.c
C_SRCS := $(filter %.c, $(SRCS))
CPP_SRCS := $(filter %.cpp, $(SRCS))

C_OBJS := $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.c.o, $(C_SRCS))
CPP_OBJS := $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.cpp.o, $(CPP_SRCS))

OBJS := $(C_OBJS) $(CPP_OBJS)
INC_DIRS := $(shell find $(SRC_DIR) -type d)

$(BUILD_DIR)/test: $(OBJS)
	$(CXX) $(CFLAGS) $(OBJS) -g -o $@
	rm -rf raw_bpf rule

$(BUILD_DIR)/%.c.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) -c $< -g -o $@

$(BUILD_DIR)/%.cpp.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -g -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) raw_bpf rule
