/**
 * Created by maomao on 2020/4/23.
 */
Java.perform(function() {
    var cn = "java.security.SecureRandom";
    var target = Java.use(cn);
    if (target) {
        target.setSeed.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setSeed";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setSeed.overloads[0].apply(this, arguments);
        };

        target.setSeed.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setSeed";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setSeed.overloads[1].apply(this, arguments);
        };
    }
});