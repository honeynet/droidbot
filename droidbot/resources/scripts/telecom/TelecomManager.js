/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.telecom.TelecomManager";
    var target = Java.use(cn);
    if (target) {
        target.isInCall.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "isInCall";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.isInCall.apply(this, arguments);
        };

        target.showInCallScreen.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "showInCallScreen";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.showInCallScreen.apply(this, arguments);
        };
    }
});