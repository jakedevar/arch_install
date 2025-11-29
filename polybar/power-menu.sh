#!/bin/bash

# Simple Power Menu using Rofi

# Options
option_lock=" Lock"
option_suspend=" Suspend"
option_logout=" Logout"
option_reboot=" Reboot"
option_poweroff=" Power Off"

# Rofi options
options="$option_lock\n$option_suspend\n$option_logout\n$option_reboot\n$option_poweroff"

# Show menu
selected=$(echo -e "$options" | rofi -dmenu -p "Power Menu" -theme-str 'window {width: 20%;} listview {lines: 5;}')

case $selected in
    "$option_lock")
        loginctl lock-session
        ;;
    "$option_suspend")
        systemctl suspend
        ;;
    "$option_logout")
        i3-msg exit
        ;;
    "$option_reboot")
        systemctl reboot
        ;;
    "$option_poweroff")
        systemctl poweroff
        ;;
esac
