/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "java.net.URL";
    var url = Java.use(cn);
    if (url) {
        //hook openConnection
        url.openConnection.overloads[0].implementation = function () {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "openConnection";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.openConnection.overloads[0].apply(this, arguments);
        };
        url.openConnection.overloads[1].implementation = function () {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "openConnection";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.openConnection.overloads[1].apply(this, arguments);
        };
        //hook openStream
        url.openStream.implementation = function() {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "openStream";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.openStream.apply(this, arguments);
        };

        url.getDefaultPort.implementation = function() {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getDefaultPort";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getDefaultPort.apply(this, arguments);
        };
    }
});
