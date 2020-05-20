/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "android.content.BroadcastReceiver";
    var broadcastReciver = Java.use(cn);
    if (broadcastReciver) {
        broadcastReciver.abortBroadcast.implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "abortBroadcast";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.abortBroadcast.apply(this, arguments);
        }
    }
});