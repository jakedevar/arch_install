#!/bin/bash

# Try AMD GPU via hwmon
if [ -f /sys/class/hwmon/hwmon4/temp1_input ]; then
    temp=$(($(cat /sys/class/hwmon/hwmon4/temp1_input) / 1000))
    echo "${temp}°C"
    exit 0
fi

# Try AMD GPU via sensors
if command -v sensors &> /dev/null; then
    temp=$(sensors amdgpu-pci-0800 2>/dev/null | grep 'edge:' | awk '{print $2}' | tr -d '+°C')
    if [ -n "$temp" ]; then
        echo "${temp}°C"
        exit 0
    fi
fi

# Try NVIDIA GPU
if command -v nvidia-smi &> /dev/null; then
    temp=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits 2>/dev/null | head -n1)
    if [ -n "$temp" ]; then
        echo "${temp}°C"
        exit 0
    fi
fi

# Fallback if no GPU temp found
echo "N/A"
