adb forward tcp:27042 tcp:27042
adb forward tcp:27043 tcp:27043

   expect -c"
   spawn adb shell
   expect \"shell@*\"
   send \"su\r\"
   expect \"root@*\"
   send \"./data/local/frida1268_64\r\"
   interact
"
