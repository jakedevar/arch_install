#!/bin/bash

# Check if voxd is running
if pgrep -x "voxd" > /dev/null; then
    echo "" # Microphone icon, running
else
    echo "%{F#707880}%{F-}" # Muted/Off icon, greyed out
fi
