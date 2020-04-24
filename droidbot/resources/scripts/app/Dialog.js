/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.app.Dialog";
    var target = Java.use(cn);
    if (target) {
        target.dispatchKeyEvent.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "dispatchKeyEvent";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.dispatchKeyEvent.apply(this, arguments);
        };

        target.setOnKeyListener.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setOnKeyListener";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setOnKeyListener.apply(this, arguments);
        };
    }
});