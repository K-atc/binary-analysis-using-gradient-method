TARGET=simple-if-statement-tree2

all: $(TARGET)

%:%.c
	$(CC) -o $@ $^
	objdump -Mintel -d $@ > $@.s

clean:
	rm -f $(TARGET)
