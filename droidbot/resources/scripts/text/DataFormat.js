/**
 * Created by maomao on 2020/4/23.
 */
Java.perform(function() {
    var cn = "java.text.DateFormat";
    var target = Java.use(cn);
    if (target) {
        target.getInstance.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getInstance";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getInstance.apply(this, arguments);
        };
    }
});