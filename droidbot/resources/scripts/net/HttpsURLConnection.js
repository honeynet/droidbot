/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "javax.net.ssl.HttpsURLConnection";
    var target = Java.use(cn);
    if (target) {
        target.setDefaultHostnameVerifier.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setDefaultHostnameVerifier";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setDefaultHostnameVerifier.apply(this, arguments);
        };
    }
});