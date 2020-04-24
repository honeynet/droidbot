/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "java.util.WeakHashMap";
    var target = Java.use(cn);
    if (target) {
        target.keySet.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "keySet";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.keySet.apply(this, arguments);
        };

        target.size.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "size";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.size.apply(this, arguments);
        };
    }
});