#!/bin/bash
# elf-tui dependency installer — auto-detect distro and install required packages
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

PKGS_CMDS="cmake gcc make pkg-config"
PKGS_LIBS="libnotcurses-dev libcapstone-dev libsqlite3-dev"

echo -e "${GREEN}==> elf-tui dependency installer${NC}"

# --- detect distro ---
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo -e "${RED}ERROR: Cannot detect Linux distribution${NC}"
    exit 1
fi

install_pkgs() {
    case "$DISTRO" in
        ubuntu|debian|linuxmint|pop)
            echo "  → Detected: $DISTRO (apt)"
            sudo apt update
            sudo apt install -y $PKGS_CMDS $PKGS_LIBS
            ;;
        fedora|rhel|centos|rocky|almalinux)
            echo "  → Detected: $DISTRO (dnf)"
            sudo dnf install -y gcc cmake make pkgconf \
                notcurses-devel capstone-devel sqlite-devel
            ;;
        arch|manjaro|endeavouros)
            echo "  → Detected: $DISTRO (pacman)"
            sudo pacman -S --noconfirm gcc cmake make pkgconf \
                notcurses capstone sqlite3
            ;;
        opensuse*|sles)
            echo "  → Detected: $DISTRO (zypper)"
            sudo zypper install -y gcc cmake make pkg-config \
                notcurses-devel capstone-devel sqlite3-devel
            ;;
        alpine)
            echo "  → Detected: $DISTRO (apk)"
            sudo apk add gcc cmake make pkgconf \
                notcurses-dev capstone-dev sqlite-dev
            ;;
        *)
            echo -e "${RED}ERROR: Unsupported distro: $DISTRO${NC}"
            echo "Please install these packages manually:"
            echo "  - notcurses  (https://github.com/dankamongmen/notcurses)"
            echo "  - capstone   (https://www.capstone-engine.org/)"
            echo "  - sqlite3    (https://www.sqlite.org/)"
            exit 1
            ;;
    esac
}

install_pkgs

echo ""
echo -e "${GREEN}==> All dependencies installed.${NC}"
echo -e "    Run: ${YELLOW}make${NC} to build elf-tui."
