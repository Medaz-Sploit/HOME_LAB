CC ?= gcc
CFLAGS ?= -Wall -O2
LDFLAGS ?= -lnetfilter_queue -lnfnetlink -lpcap -lpthread

TARGET = packet-interceptor
SOURCES = packet-interceptor.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean