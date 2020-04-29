CC      = gcc
CFLAGS  = -g -std=c99 -Wall -DDATE=\"`date +%Y%m%d`\"
LIBS    =
OBJS    = syscalls.o elf.o const.o
TARGET  = sl-tracer
MAIN    = main.c

all: $(OBJS)
	$(CC) -o $(TARGET) $(MAIN) $(CFLAGS) $(LIBS) $(OBJS)

clean:
	rm -rf *.o $(TARGET)

