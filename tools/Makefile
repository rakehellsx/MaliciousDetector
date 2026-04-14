# Makefile for gen_data
# 用法: make  或  make clean

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11
LDFLAGS = $(shell pkg-config --libs libcjson) -lsqlite3
INCS    = $(shell pkg-config --cflags libcjson)

TARGET  = gen_data
SRC     = gen_data.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCS) -o $@ $^ $(LDFLAGS)
	@echo "编译成功: ./$(TARGET)"

clean:
	rm -f $(TARGET)
