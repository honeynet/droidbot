/**
 * Created by maomao on 2020/4/23.
 */
Java.perform(function() {
    var cn = "java.nio.channels.FileChannel";
    var target = Java.use(cn);
    if (target) {
        target.lock.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "lock";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.lock.overloads[0].apply(this, arguments);
        };
        target.lock.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "lock";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.lock.overloads[1].apply(this, arguments);
        };
    }
});