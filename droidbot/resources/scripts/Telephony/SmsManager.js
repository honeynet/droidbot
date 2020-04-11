Java.perform(function() {
    var cn = "android.telephony.SmsManager";
    var smsManager = Java.use(cn);
    if (smsManager) {
        //hook sendTextMessage
        smsManager.sendTextMessage.overloads[0].implementation = function(dest) {
            send("call " + cn + "->sendTextMessage for " + arguments[0] + " " + arguments[2]);
            return this.sendTextMessage.overloads[0].apply(this, arguments);
        };
        //hook sendDataMessage
        smsManager.sendDataMessage.overloads[0].implementation = function(dest) {
            send("call " + cn + "->sendDataMessage for " + dest);
            return this.sendDataMessage.overloads[0].apply(this, arguments);
        };
        //hook sendMultipartTextMessage
        smsManager.sendMultipartTextMessage.overloads[0].implementation = function(dest) {
            send("call " + cn + "->sendMultipartTextMessage for " + dest);
            return this.sendMultipartTextMessage.overloads[0].apply(this, arguments);
        };
    }
});
