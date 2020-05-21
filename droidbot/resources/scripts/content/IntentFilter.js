/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.content.IntentFilter";
    var target = Java.use(cn);
    if (target) {
        target.setPriority.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setPriority";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setPriority.apply(this, arguments);
        };
    }
});