/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "java.lang.Character";
    var target = Java.use(cn);
    if (target) {
        target.$init.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "$init";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.$init.apply(this, arguments);
        };

        target.toTitleCase.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "toTitleCase";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.toTitleCase.overloads[0].apply(this, arguments);
        };
        target.toTitleCase.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "toTitleCase";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.toTitleCase.overloads[1].apply(this, arguments);
        };
    }
});