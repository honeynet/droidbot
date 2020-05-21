/**
 * Created by maomao on 2020/4/23.
 */
Java.perform(function() {
    var cn = "java.security.cert.CertificateException";
    var target = Java.use(cn);
    if (target) {
        target.printStackTrace.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "printStackTrace";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.printStackTrace.overloads[0].apply(this, arguments);
        };
        target.printStackTrace.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "printStackTrace";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.printStackTrace.overloads[1].apply(this, arguments);
        };
        // target.printStackTrace.overloads[2].implementation = function(dest) {
        //     var myArray=new Array()
        //     myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
        //     myArray[1] = cn + "." + "printStackTrace";
        //     myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
        //     send(myArray);
        //     return this.printStackTrace.overloads[2].apply(this, arguments);
        // };
        // target.printStackTrace.overloads[3].implementation = function(dest) {
        //     var myArray=new Array()
        //     myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
        //     myArray[1] = cn + "." + "printStackTrace";
        //     myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
        //     send(myArray);
        //     return this.printStackTrace.overloads[3].apply(this, arguments);
        // };
    }
});