#!/bin/bash

# Define the terminal workspace number
TERMINAL_WORKSPACE="10"

# Get the current focused workspace number using python to parse JSON
current_workspace=$(i3-msg -t get_workspaces | python3 -c "import sys, json; print(next((w['num'] for w in json.load(sys.stdin) if w['focused']), ''))")

# Check if we are currently on the terminal workspace
if [ "$current_workspace" -eq "$TERMINAL_WORKSPACE" ]; then
    # If on terminal workspace, go back to the previous workspace
    i3-msg workspace back_and_forth
else
    # If not on terminal workspace, go to the terminal workspace
    i3-msg workspace number "$TERMINAL_WORKSPACE"
fi