/**
 * Created by maomao on 2020/4/23.
 */
Java.perform(function() {
    var cn = "java.util.concurrent.ThreadPoolExecutor";
    var target = Java.use(cn);
    if (target) {
        target.getActiveCount.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getActiveCount";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getActiveCount.apply(this, arguments);
        };

        target.getCompletedTaskCount.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getCompletedTaskCount";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getCompletedTaskCount.apply(this, arguments);
        };

        target.getTaskCount.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getTaskCount";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getTaskCount.apply(this, arguments);
        };
    }
});