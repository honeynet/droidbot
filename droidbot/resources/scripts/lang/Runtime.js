/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "java.lang.Runtime";
    var runtime = Java.use(cn);
    if (runtime) {
        runtime.exec.overload("java.lang.String").implementation = function(cmd) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "exec";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.exec.overload("java.lang.String").apply(this, arguments);
        };
    }
});
