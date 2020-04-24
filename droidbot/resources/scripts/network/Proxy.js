/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.net.Proxy";
    var target = Java.use(cn);
    if (target) {
        target.getDefaultHost.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getDefaultHost";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getDefaultHost.apply(this, arguments);
        };

        target.getDefaultPort.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getDefaultPort";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getDefaultPort.apply(this, arguments);
        };
    }
});