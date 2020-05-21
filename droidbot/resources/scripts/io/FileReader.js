/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "java.io.FileReader";
    var target = Java.use(cn);
    if (target) {
        target.read.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "read";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.read.overloads[0].apply(this, arguments);
        };
        target.read.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "read";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.read.overloads[1].apply(this, arguments);
        };
    }
});