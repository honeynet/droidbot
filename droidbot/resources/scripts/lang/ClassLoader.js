/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "java.lang.ClassLoader";
    var target = Java.use(cn);
    if (target) {
        target.getParent.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getParent";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getParent.apply(this, arguments);
        };
    }
});