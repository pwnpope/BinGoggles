SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin

CFLAGS := -O0 -g 
LDFLAGS := -static

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
TARGETS := $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%, $(SRCS))

all: $(TARGETS) rm_obj

$(BIN_DIR)/%: $(OBJ_DIR)/%.o
	@mkdir -p $(BIN_DIR)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

rm_obj:
	@rm -rf $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean rm_obj
