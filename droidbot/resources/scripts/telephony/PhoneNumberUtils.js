/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.telephony.PhoneNumberUtils";
    var target = Java.use(cn);
    if (target) {
        target.isVoiceMailNumber.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "isVoiceMailNumber";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.isVoiceMailNumber.overloads[0].apply(this, arguments);
        };

        target.isVoiceMailNumber.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "isVoiceMailNumber";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.isVoiceMailNumber.overloads[1].apply(this, arguments);
        };

        target.isVoiceMailNumber.overloads[2].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "isVoiceMailNumber";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.isVoiceMailNumber.overloads[2].apply(this, arguments);
        };
    }
});