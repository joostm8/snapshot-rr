CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra
BUILD   := build

all: $(BUILD)/controller $(BUILD)/launcher $(BUILD)/supervisor $(BUILD)/plant

$(BUILD)/%: src/%.c src/common.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(if $(filter controller plant,$*),-lm)

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD) run

.PHONY: all clean
