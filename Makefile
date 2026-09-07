CC = gcc
CFLAGS = -Wall -Wextra -O2

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = $(BUILD_DIR)/bin
OBJ_DIR = $(BUILD_DIR)/obj

TARGET = $(BIN_DIR)/traceroute
SRCS = $(SRC_DIR)/traceroute.c $(SRC_DIR)/packet.c
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJS)
	@cp -f $@ traceroute

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(SRC_DIR)/packet.h
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) traceroute


