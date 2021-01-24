/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "dalvik.system.DexClassLoader";
    var target = Java.use(cn);
    if (target) {
        target.findLibrary.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "findLibrary";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.findLibrary.apply(this, arguments);
        };
    }
});