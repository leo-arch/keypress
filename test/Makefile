CFLAGS = -I../src
SRC = test.c ../src/translate_key.c

TARGET = test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
