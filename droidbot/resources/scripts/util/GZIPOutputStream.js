/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "java.util.zip.GZIPOutputStream";
    var target = Java.use(cn);
    if (target) {
        target.finish.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "finish";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.finish.apply(this, arguments);
        };

        target.flush.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "flush";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.flush.apply(this, arguments);
        };
    }
});
