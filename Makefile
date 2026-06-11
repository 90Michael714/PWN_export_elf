.PHONY: all clean

all: build/elf-tui

build/elf-tui:
	@mkdir -p build
	@cd build && cmake .. && make

clean:
	rm -rf build
