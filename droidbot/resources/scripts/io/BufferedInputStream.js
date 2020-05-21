/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "java.io.BufferedInputStream";
    var target = Java.use(cn);
    if (target) {
        target.mark.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "mark";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.mark.apply(this, arguments);
        };

        target.reset.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "reset";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.reset.apply(this, arguments);
        };
    }
});