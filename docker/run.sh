#!/bin/bash
if [ "$1" = "NONE" ]; then
    echo "Usage: sudo docker run -it --rm -v ~/samples:/samples:ro -v ~/samples/out/:/samples/out honeynet/droidbox /samples/filename.apk [duration in seconds]"
    exit 1
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
echo `date` ": Start DroitBox"
python /opt/DroidBox_4.1.1/scripts/droidbox.py $1 $2 2>&1 |tee /samples/out/analysis.log &

#Bad workaround, because DroitBot crashes, if Emulator is not ready.
sleep 150
echo `date` ": Start DroitBot"
python /opt/DroidBot/start.py -a $1 2>&1 |tee /samples/out/droidbot.log
echo -ne "\e[0m"
exit
