#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Define output files
PACMAN_FILE="$SCRIPT_DIR/pacman_packages.txt"
YAY_FILE="$SCRIPT_DIR/yay_packages.txt"

echo "Generating package lists..."

# Get explicitly installed native packages (Pacman)
# -Q: Query
# -q: Quiet (names only)
# -e: Explicitly installed
# -n: Native targets
if pacman -Qqen > "$PACMAN_FILE"; then
    echo "Successfully saved native packages to $PACMAN_FILE"
else
    echo "Error saving native packages"
fi

# Get explicitly installed foreign packages (Yay/AUR)
# -m: Foreign targets (installed from AUR)
if pacman -Qqem > "$YAY_FILE"; then
    echo "Successfully saved AUR/Yay packages to $YAY_FILE"
else
    echo "Error saving AUR packages"
fi
