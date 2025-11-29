#!/bin/bash

# Default color from polybar config (colors.volume)
DEFAULT_COLOR="#a6e3a1"
STATE_FILE="/tmp/polybar_now_playing_state"

while true; do
    # Get Volume (left channel)
    VOL=$(pactl get-sink-volume @DEFAULT_SINK@ | grep -oP '\d+(?=%)' | head -n 1)
    
    # Get Mute Status
    MUTE=$(pactl get-sink-mute @DEFAULT_SINK@)
    
    # Determine Color
    COLOR="$DEFAULT_COLOR"
    if [ -f "$STATE_FILE" ]; then
        # Use a subshell to source safely and avoid polluting main shell vars if we expand logic later
        FILE_COLOR=$(source "$STATE_FILE" && echo "$current_color")
        if [ -n "$FILE_COLOR" ]; then
            COLOR="$FILE_COLOR"
        fi
    fi

    # Determine Icon and Text
    if [[ "$MUTE" == *"yes"* ]]; then
        ICON=""
        TEXT="muted"
    else
        # Handle case where VOL might be empty if pactl fails
        if [ -z "$VOL" ]; then VOL=0; fi
        
        if [ "$VOL" -eq 0 ]; then
            ICON=""
        elif [ "$VOL" -lt 50 ]; then
            ICON=""
        else
            ICON=""
        fi
        TEXT="$VOL%"
    fi

    # Output formatted string
    echo "%{F$COLOR}$ICON $TEXT%{F-}"
    
    # Update rate (fast for responsiveness)
    sleep 0.1
done
