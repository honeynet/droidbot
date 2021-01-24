/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.util.Base64";
    var target = Java.use(cn);
    if (target) {
        target.encode.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "encode";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.encode.overloads[0].apply(this, arguments);
        };
        target.encode.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "encode";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.encode.overloads[1].apply(this, arguments);
        };
    }
});