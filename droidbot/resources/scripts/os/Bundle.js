/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.os.Bundle";
    var target = Java.use(cn);
    if (target) {
        target.getClassLoader.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getClassLoader";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getClassLoader.apply(this, arguments);
        };
    }
});