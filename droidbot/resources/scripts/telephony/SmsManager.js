/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "android.telephony.SmsManager";
    var smsManager = Java.use(cn);
    if (smsManager) {
        //hook sendTextMessage
        smsManager.sendTextMessage.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "sendTextMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.sendTextMessage.overloads[0].apply(this, arguments);
        };
        //hook sendDataMessage
        smsManager.sendDataMessage.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "sendDataMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.sendDataMessage.overloads[0].apply(this, arguments);
        };
        //hook sendMultipartTextMessage
        smsManager.sendMultipartTextMessage.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "sendMultipartTextMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.sendMultipartTextMessage.overloads[0].apply(this, arguments);
        };

        smsManager.sendTextMessage.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "sendTextMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.sendTextMessage.overloads[0].apply(this, arguments);
        };

        smsManager.sendTextMessage.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "sendTextMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.sendTextMessage.overloads[0].apply(this, arguments);
        };

        smsManager.divideMessage.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "divideMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.divideMessage.apply(this, arguments);
        };

        smsManager.downloadMultimediaMessage.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "downloadMultimediaMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.downloadMultimediaMessage.apply(this, arguments);
        };

        smsManager.sendMultimediaMessage.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "sendMultimediaMessage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.sendMultimediaMessage.apply(this, arguments);
        };
    }
});
