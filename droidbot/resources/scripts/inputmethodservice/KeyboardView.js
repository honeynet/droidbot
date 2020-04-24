/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.inputmethodservice.KeyboardView";
    var target = Java.use(cn);
    if (target) {
        target.swipeDown.implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "swipeDown";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.swipeDown.apply(this, arguments);
        };

        target.swipeRight.implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "swipeRight";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.swipeRight.apply(this, arguments);
        };
    }
});