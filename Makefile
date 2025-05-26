TARGET := ceccomp test check

SRC_DIR := ./src
INC_DIR := ./include
TEST_DIR := ./test
BUILD_DIR := ./build
BUILD_UTIL := ./build/utils

C_SRCS := $(shell find $(SRC_DIR) ! -name 'ceccomp.c' -name '*.c' -or -name '*.s')
TEST_SRCS := $(shell find $(TEST_DIR) -name '*.c')

OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.c.o,$(C_SRCS))
TEST_OBJS := $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/%.c.o,$(TEST_SRCS))

CECCOMP_MAIN := $(BUILD_DIR)/ceccomp.c.o

CC := gcc

CFLAGS := -fpie -fstack-protector -Wall -Wextra
LDFLAGS := -lseccomp -z now -z noexecstack -fpie -fstack-protector -Wall -Wextra

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
ZSH_SRC := ./completions

all: ceccomp test check

install: bin_install zsh_cmp_install
	@echo "install success"

bin_install: ceccomp
	mkdir -p $(BIN_DIR)
	cp $(BUILD_DIR)/$< $(BIN_DIR)/$<

zsh_cmp_install: $(ZSH_SRC)/_ceccomp
	mkdir -p $(ZSH_DST)
	cp $< $(ZSH_DST)/_ceccomp

ceccomp: $(OBJS) $(CECCOMP_MAIN)
	$(CC) $(LDFLAGS) $^ -o $@
	mv -f $@ $(BUILD_DIR)
	@echo "ceccomp is made"
	@echo ""

test: $(TEST_OBJS)
	$(CC) $(CFLAGS) $^ -o $(BUILD_DIR)/$@
	@echo "test is made"
	@echo ""

$(BUILD_DIR)/%.c.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@
$(BUILD_DIR)/%.cpp.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@
$(BUILD_DIR)/%.c.o: $(TEST_DIR)/%.c | $(BUILD_DIR)
	$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR) $(BUILD_UTIL) $(BUILD_TEST)

check: check_disasm check_asm check_emu

check_disasm:
	make ceccomp DEBUG=1 -B
	cat bpf/* | ./build/ceccomp disasm > result_testdisasm
	cat bpf/* | ceccomp disasm > result_disasm
	diff result_testdisasm result_disasm
	@echo disasm test passed
	@echo ""

check_asm:
	make ceccomp DEBUG=1 -B
	./build/ceccomp asm disasm_result --fmt hexfmt > result_testasm
	ceccomp asm disasm_result --fmt hexfmt > result_asm
	diff result_testasm result_asm
	@echo asm test passed
	@echo ""

check_emu:
	make ceccomp DEBUG=1 -B
	number=0; \
	while [ "$$number" -lt 100 ]; do \
		./build/ceccomp emu result_disasm $$number > result_testemu; \
		ceccomp emu result_disasm $$number > result_emu; \
		diff result_emu result_testemu; \
		number=$$(($$number+1)); \
	done
	@echo emu test passed
	@echo ""


.PHONY: clean all check check_disasm check_asm check_emu
clean:
	rm -rf $(BUILD_DIR)
