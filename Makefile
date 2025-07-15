CC = gcc
CFLAGS = -O2 -march=native -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wall -Wextra -pedantic
LDFLAGS =
TARGET = syscall_tracer
SRC = main.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)
