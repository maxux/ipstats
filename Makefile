EXEC = lantraffic

CFLAGS  = -g -W -Wall -O2
LDFLAGS = -lpcap

SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)

all: LDFLAGS += -lhiredis
all: $(EXEC)

noredis: CFLAGS += -DNOREDIS
noredis: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -fv *.o

mrproper: clean
	rm -fv $(EXEC)

