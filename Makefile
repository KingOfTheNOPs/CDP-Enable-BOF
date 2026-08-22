CC=x86_64-w64-mingw32-gcc
OBJCOPY=objcopy
CFLAGS=-O2 -c -Wall -Wextra -ffreestanding -fno-builtin -fno-tree-loop-distribute-patterns -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-exceptions -fno-stack-protector
INCLUDES=-I .
OUT=cdp_enable_bof.o
ISO_OUT=cdp_enable_iso_bof.o

.PHONY: all clean

all: $(OUT) $(ISO_OUT)

$(OUT): cdp_enable_bof.c
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES)
	$(OBJCOPY) --remove-section .pdata --remove-section .xdata --remove-section .eh_frame $@

$(ISO_OUT): cdp_enable_iso_bof.c
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES)
	$(OBJCOPY) --remove-section .pdata --remove-section .xdata --remove-section .eh_frame $@

clean:
	rm -f $(OUT) $(ISO_OUT)
