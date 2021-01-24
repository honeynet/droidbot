/**
 * Created by maomao on 2020/4/23.
 */
Java.perform(function() {
    var cn = "java.net.URLClassLoader";
    var target = Java.use(cn);
    if (target) {
        // target.loadClass.overloads[0].implementation = function(dest) {
        //     var myArray=new Array()
        //     myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
        //     myArray[1] = cn + "." + "loadClass";
        //     myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
        //     send(myArray);
        //     return this.loadClass.overloads[0].apply(this, arguments);
        // };
        // target.loadClass.overloads[1].implementation = function(dest) {
        //     var myArray=new Array()
        //     myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
        //     myArray[1] = cn + "." + "loadClass";
        //     myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
        //     send(myArray);
        //     return this.loadClass.overloads[1].apply(this, arguments);
        // };

        target.$init.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "init";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.$init.overloads[0].apply(this, arguments);
        };
        target.$init.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "init";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.$init.overloads[1].apply(this, arguments);
        };
        target.$init.overloads[2].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "init";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.$init.overloads[2].apply(this, arguments);
        };
    }
});