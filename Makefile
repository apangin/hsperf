CPPFLAGS ?= -D_GNU_SOURCE
CFLAGS ?= -O3

.PHONY: clean

hsperf: hsperf.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f hsperf
