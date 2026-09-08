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

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS)
	@cp -f $@ traceroute

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) traceroute
