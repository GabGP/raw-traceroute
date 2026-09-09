CC = gcc
CFLAGS = -Wall -Wextra -O2

SRC_DIR = src
TESTS_DIR = tests
BUILD_DIR = build
BIN_DIR = $(BUILD_DIR)/bin
OBJ_DIR = $(BUILD_DIR)/obj

# Layered subdirectories and include search paths
SRC_SUBDIRS = $(SRC_DIR)/proto $(SRC_DIR)/engine $(SRC_DIR)/app
INCLUDES = $(addprefix -I,$(SRC_SUBDIRS))

TARGET = $(BIN_DIR)/traceroute
SRCS = $(foreach d,$(SRC_SUBDIRS),$(wildcard $(d)/*.c))
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

TEST_BIN = $(BIN_DIR)/test_packet
TEST_OBJS = $(OBJ_DIR)/test_packet.o \
            $(OBJ_DIR)/proto/checksum.o \
            $(OBJ_DIR)/proto/ip_header.o \
            $(OBJ_DIR)/proto/udp_header.o \
            $(OBJ_DIR)/proto/icmp_header.o \
            $(OBJ_DIR)/proto/packet.o

.PHONY: all clean test test-integration

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS)
	@cp -f $@ traceroute

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJ_DIR)/test_packet.o: $(TESTS_DIR)/test_packet.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TEST_BIN): $(TEST_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

test: all $(TEST_BIN)
	@echo "=== Running Tier A Unit Tests ==="
	@$(TEST_BIN)
	@echo
	@echo "=== Running Tier B CLI Tests ==="
	@$(TESTS_DIR)/test_cli.sh

test-integration: all
	@$(TESTS_DIR)/test_integration.sh

clean:
	rm -rf $(BUILD_DIR) traceroute
