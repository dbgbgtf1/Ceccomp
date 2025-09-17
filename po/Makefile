GREEN := $(shell printf '\033[32m')
RESET := $(shell printf '\033[0m')
ECHO_NOPROG = printf "    $(1)\t$(2)\n"

INC_DIR := ../include
SRC_DIR := ../src
INC_SRCS := $(shell find $(INC_DIR) -name '*.h')
C_SRCS := $(shell find $(SRC_DIR) -name '*.c' -or -name '*.s')

SOURCES_LIST := SOURCES.txt
POT_FILE := ceccomp.pot
PO_ZHCN := zh_CN.po

all: $(PO_ZHCN)
	$Q$(call ECHO_NOPROG,$(GREEN)UPDATED,po$(RESET))

$(SOURCES_LIST): $(INC_SRCS) $(C_SRCS)
	$Q$(call ECHO_NOPROG,TR,$@)
	$Qecho $^ | tr ' ' '\n' > $@

$(POT_FILE): $(SOURCES_LIST)
	$Q$(call ECHO_NOPROG,XGETTEXT,$@)
	$Qxgettext -k_ -o $@ -f $<

$(PO_ZHCN): $(POT_FILE)
	$Q$(call ECHO_NOPROG,MSGMERGE,$@)
	$Qmsgmerge --previous --update $@ $< 2> /dev/null
