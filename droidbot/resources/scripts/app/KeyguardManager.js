/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.app.KeyguardManager";
    var target = Java.use(cn);
    if (target) {
        target.exitKeyguardSecurely.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "exitKeyguardSecurely";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.exitKeyguardSecurely.apply(this, arguments);
        };
    }
});