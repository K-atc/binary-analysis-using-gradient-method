TARGET=simple-if-statement-tree

all: $(TARGET)

%:%.c
	$(CC) -o $@ $^
	objdump -Mintel -d $@ > $@.s

clean:
	rm -f $(TARGET) *.s
