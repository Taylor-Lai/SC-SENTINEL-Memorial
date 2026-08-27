CC ?= gcc
CFLAGS ?= -Iinclude -Wall -Wextra -Werror
SRCS := src/gziprelay.c src/main.c
TARGET := gziprelay

.PHONY: all asan test clean
all:
	$(CC) $(CFLAGS) -O2 -o $(TARGET) $(SRCS)
asan:
	$(CC) $(CFLAGS) -O1 -g -fsanitize=address -fno-omit-frame-pointer -o $(TARGET) $(SRCS)
test: all
	@printf '' | ./$(TARGET)
clean:
	rm -f $(TARGET)
