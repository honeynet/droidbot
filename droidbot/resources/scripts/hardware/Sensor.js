/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.hardware.Sensor";
    var target = Java.use(cn);
    if (target) {
        target.getName.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getName";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getName.apply(this, arguments);
        };

        target.getVendor.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getVendor";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getVendor.apply(this, arguments);
        };

        target.getVersion.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getVersion";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getVersion.apply(this, arguments);
        };
    }
});