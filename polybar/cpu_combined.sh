#!/bin/bash

CPU_USAGE=$(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print int(usage)}')
CPU_TEMP=$(cat /sys/class/hwmon/hwmon5/temp1_input 2>/dev/null | awk '{print int($1/1000)}')

if [ -z "$CPU_TEMP" ]; then
    CPU_TEMP="N/A" # Fallback if temp not found
else
    CPU_TEMP="${CPU_TEMP}°C"
fi

echo "CPU ${CPU_USAGE}% ${CPU_TEMP} |"
