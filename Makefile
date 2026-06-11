.PHONY: all clean deps check

all: build/elf-tui

build/elf-tui:
	@mkdir -p build
	@cd build && cmake .. && make

# ── 依赖检查 ──
check:
	@echo "==> Checking build dependencies..."
	@missing=""; \
	for cmd in cmake gcc make pkg-config; do \
		if command -v $$cmd >/dev/null 2>&1; then \
			echo "  ✓ $$cmd"; \
		else \
			echo "  ✗ $$cmd (missing)"; missing="$$missing $$cmd"; \
		fi; \
	done; \
	for lib in notcurses capstone sqlite3; do \
		if pkg-config --exists $$lib 2>/dev/null; then \
			ver=$$(pkg-config --modversion $$lib 2>/dev/null); \
			echo "  ✓ $$lib $$ver"; \
		else \
			echo "  ✗ $$lib (missing)"; missing="$$missing $$lib"; \
		fi; \
	done; \
	if [ -n "$$missing" ]; then \
		echo ""; \
		echo "  Missing:$$missing"; \
		echo "  Run: make deps    (auto-install for your distro)"; \
		echo "   Or: sudo apt install libnotcurses-dev libcapstone-dev libsqlite3-dev cmake gcc"; \
		exit 1; \
	else \
		echo ""; \
		echo "  All dependencies satisfied. Run: make"; \
	fi

# ── 自动安装依赖 ──
deps:
	@if [ -f scripts/install_deps.sh ]; then \
		bash scripts/install_deps.sh; \
	else \
		echo "Missing scripts/install_deps.sh"; \
		echo "Manual install:"; \
		echo "  Ubuntu/Debian: sudo apt install cmake gcc make libnotcurses-dev libcapstone-dev libsqlite3-dev"; \
		echo "  Fedora:        sudo dnf install gcc cmake make notcurses-devel capstone-devel sqlite-devel"; \
		echo "  Arch:          sudo pacman -S gcc cmake make notcurses capstone sqlite3"; \
	fi

clean:
	rm -rf build
