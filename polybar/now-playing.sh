#!/bin/bash

player_status=$(playerctl status 2> /dev/null)

if [ "$player_status" = "Playing" ]; then
    title=$(playerctl metadata xesam:title)
    artist=$(playerctl metadata xesam:artist)
    # Escape special characters for safety, though polybar handles utf8 well.
    
    # Get player name to decide icon
    player=$(playerctl metadata --format "{{ playerName }}")
    
    # Default icon
    icon=""
    
    if [[ "$player" == *"spotify"* ]]; then
        icon=""
    elif [[ "$player" == *"firefox"* || "$player" == *"chrome"* || "$player" == *"chromium"* ]]; then
        # Try to detect youtube in title if playing from browser
        # This is heuristic and depends on the browser reporting the title correctly
        if [[ "$title" == *"YouTube"* ]]; then
             icon=""
        else
             icon="" # Browser icon fallback or specific browser icon
        fi
    fi
    
    # If artist is empty, just show title
    if [ -n "$artist" ]; then
        echo "$icon $artist - $title"
    else
        echo "$icon $title"
    fi
else
    echo ""
fi
