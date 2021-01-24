/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "org.apache.http.params.HttpConnectionParams";
    var target = Java.use(cn);
    if (target) {
        target.setStaleCheckingEnabled.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setStaleCheckingEnabled";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setStaleCheckingEnabled.apply(this, arguments);
        };
    }
});