#!/bin/bash
if [ "$1" = "NONE" ]; then
    echo "Usage: sudo docker run -it --rm -v ~/samples:/samples:ro -v ~/samples/out/:/samples/out honeynet/droidbox /samples/filename.apk [duration in seconds]"
    exit 1
fi
#Make $2 optional and save as $duration
if [ "$2" = "" ]; then
    duration=0
else
    duration=$2
fi
echo -e "\e[1;32;40mDroidbox Docker starting\nWaiting for the emulator to startup..."
mkdir -p /samples/out
/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}' > /samples/out/ip.txt
sleep 1
/opt/android-sdk-linux/tools/emulator64-arm @droidbox -no-window -no-audio -system /opt/DroidBox_4.1.1/images/system.img -ramdisk /opt/DroidBox_4.1.1/images/ramdisk.img  >> /samples/out/emulator.log &
sleep 1
service ssh start
adb wait-for-device 
adb forward tcp:5900 tcp:5901
adb shell /data/fastdroid-vnc >> /samples/out/vnc.log &
echo -ne "\e[0m"
echo `date` ": Start DroitBot with DroidBox"
#TODO: If we call Python direct, a Docker stop does not send a sigterm to this python job.
droidbot -d emulator-5554 -a $1 -duration $duration -event dynamic -o /samples/out/ -q -droidbox 2>&1 |tee /samples/out/analysis.log
echo -ne "\e[0m"
exit
