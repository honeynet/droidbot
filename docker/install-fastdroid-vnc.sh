#!/bin/sh
emulator64-arm @droidbox -no-window -no-audio &
sleep 5
adb wait-for-device && adb push /build/fastdroid-vnc /data && adb shell chmod 755 /data/fastdroid-vnc 
adb shell reboot -p
