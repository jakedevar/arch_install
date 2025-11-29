#!/bin/bash

player_status=$(playerctl status 2> /dev/null)

if [ "$player_status" = "Playing" ]; then
    title=$(playerctl metadata xesam:title)
    artist=$(playerctl metadata xesam:artist)
    # Escape special characters for safety
    
    # Get player name to decide icon
    player=$(playerctl metadata --format "{{ playerName }}")
    
    # Default icon
    icon=""
    
    if [[ "$player" == *"spotify"* ]]; then
        icon=""
    elif [[ "$player" == *"firefox"* || "$player" == *"chrome"* || "$player" == *"chromium"* ]]; then
        if [[ "$title" == *"YouTube"* ]]; then
             icon=""
        else
             icon=""
        fi
    fi
    
    # Logic for random color
    state_file="/tmp/polybar_now_playing_state"
    current_id="$player_status|$artist|$title"
    
    if [ -f "$state_file" ]; then
        source "$state_file"
    fi

    if [ "$current_id" != "$last_id" ]; then
        # Generate a random pastel/bright color
        # Min 100 to ensure visibility on dark bg
        r=$((RANDOM % 156 + 100))
        g=$((RANDOM % 156 + 100))
        b=$((RANDOM % 156 + 100))
        current_color=$(printf "#%02x%02x%02x" $r $g $b)
        
        last_id="$current_id"
        # Save state
        echo "last_id=\"$last_id\"" > "$state_file"
        echo "current_color=\"$current_color\"" >> "$state_file"
    fi

    # If artist is empty, just show title
    if [ -n "$artist" ]; then
        echo "%{F$current_color}$icon $artist - $title%{F-}"
    else
        echo "%{F$current_color}$icon $title%{F-}"
    fi
else
    # Not playing - Clear color in state file so volume reverts to default
    state_file="/tmp/polybar_now_playing_state"
    echo "current_color=\"\"" > "$state_file"
    echo ""
fi

