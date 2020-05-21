/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "javax.crypto.Cipher";
    var cipher = Java.use(cn);
    if (cipher) {
        cipher.getInstance.overloads[0].implementation = function(transformation) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getInstance";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getInstance.overloads[0].apply(this, arguments);
        }
        cipher.getInstance.overloads[1].implementation = function(transformation) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getInstance";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getInstance.overloads[1].apply(this, arguments);
        }
        cipher.getInstance.overloads[2].implementation = function(transformation) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getInstance";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getInstance.overloads[2].apply(this, arguments);
        }

        cipher.getBlockSize.implementation = function(transformation) {
            var myArray=new Array()
            myArray[0] = ""  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getBlockSize";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getBlockSize.apply(this, arguments);
        }
    }
});