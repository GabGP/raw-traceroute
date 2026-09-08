CC = gcc
CFLAGS = -Wall -Wextra -O2

SRC_DIR = src
TESTS_DIR = tests
BUILD_DIR = build
BIN_DIR = $(BUILD_DIR)/bin
OBJ_DIR = $(BUILD_DIR)/obj

TARGET = $(BIN_DIR)/traceroute
SRCS = $(SRC_DIR)/traceroute.c $(SRC_DIR)/packet.c $(SRC_DIR)/cli.c $(SRC_DIR)/network.c $(SRC_DIR)/probe.c
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

TEST_BIN = $(BIN_DIR)/test_packet

.PHONY: all clean test test-integration

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS)
	@cp -f $@ traceroute

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/test_packet.o: $(TESTS_DIR)/test_packet.c $(SRC_DIR)/packet.h
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(TEST_BIN): $(OBJ_DIR)/test_packet.o $(OBJ_DIR)/packet.o
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
