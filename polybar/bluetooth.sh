#!/bin/bash
if [ $(bluetoothctl show | grep "Powered: yes" | wc -l) -eq 0 ]
then
  echo "%{F#66ffffff}"
else
  if [ $(echo info | bluetoothctl | grep 'Device' | wc -l) -eq 0 ]
  then 
    echo ""
  else
    echo "%{F#89b4fa}"
  fi
fi
