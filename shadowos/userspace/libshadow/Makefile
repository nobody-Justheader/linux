CC=gcc
CFLAGS=-Wall -fPIC
LDFLAGS=-shared

TARGET=libshadow.so
SRCS=libshadow.c
OBJS=$(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
