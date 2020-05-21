/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.speech.SpeechRecognizer";
    var target = Java.use(cn);
    if (target) {
        target.cancel.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "cancel";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.cancel.apply(this, arguments);
        };

        target.setRecognitionListener.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setRecognitionListener";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setRecognitionListener.apply(this, arguments);
        };

        target.startListening.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "startListening";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.startListening.apply(this, arguments);
        };

        target.stopListening.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "stopListening";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.stopListening.apply(this, arguments);
        };
    }
});