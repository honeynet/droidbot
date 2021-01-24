/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.media.MediaRecorder";
    var target = Java.use(cn);
    if (target) {
        target.setAudioSource.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setAudioSource";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setAudioSource.apply(this, arguments);
        };

        target.setVideoSource.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setVideoSource";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setVideoSource.apply(this, arguments);
        };
    }
});