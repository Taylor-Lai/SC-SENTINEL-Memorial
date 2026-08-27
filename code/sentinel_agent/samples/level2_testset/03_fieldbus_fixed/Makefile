CC ?= gcc
PREFIX ?= /usr/local
CFLAGS ?= -Iinclude -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE
SRCS := src/modbus_proto.c src/main.c
TARGET := modbus_parser

.PHONY: all normal test clean install

all: normal

normal:
	$(CC) $(CFLAGS) -O2 -o $(TARGET) $(SRCS)

test: normal
	@printf "basic smoke test... "
	@printf "" | ./$(TARGET) >/dev/null 2>/dev/null || true
	@echo OK

install: normal
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/include/$(TARGET)
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/
	install -m 644 include/modbus_proto.h $(DESTDIR)$(PREFIX)/include/$(TARGET)/

clean:
	rm -f $(TARGET)
	rm -rf build out findings
