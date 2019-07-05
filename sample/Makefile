TARGET=simple-if-statement-tree simple-elf-checker traceme function

all: $(TARGET)

%:%.c
	$(CC) -o $@ $^
	objdump -Mintel -d $@ > $@.s

clean:
	rm -f $(TARGET) *.s
