Java.perform(function() {
    var cn = "android.content.BroadcastReceiver";
    var broadcastReciver = Java.use(cn);
    if (broadcastReciver) {
        broadcastReciver.abortBroadcast.implementation = function() {
            send("call " + cn + "->abortBroadcast");
            return this.abortBroadcast.apply(this, arguments);
        }
    }
});