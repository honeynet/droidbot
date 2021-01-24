/**
 * Created by wsh on 2020/4/12.
 */
Java.perform(function () {
    var cn = "android.net.ConnectivityManager";
    var manager = Java.use(cn);
    if(manager) {
        manager.getNetworkInfo.overloads[0].implementaion = function () {
            var myArray=new Array()
            myArray[0] = ""  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getNetworkInfo";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getNetworkInfo.overloads[0].apply(this, arguments);
        };

        manager.getNetworkInfo.overloads[1].implementaion = function () {
            var myArray=new Array()
            myArray[0] = ""  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getNetworkInfo";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getNetworkInfo.overloads[1].apply(this, arguments);
        };

        manager.getAllNetworkInfo.implementation = function () {
            var myArray=new Array()
            myArray[0] = ""  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getAllNetworkInfo";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getAllNetworkInfo.apply(this, arguments);
        };

        manager.getActiveNetworkInfo.implementation = function () {
            var myArray=new Array()
            myArray[0] = ""  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getActiveNetworkInfo";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getActiveNetworkInfo.apply(this, arguments);
        };

        manager.startUsingNetworkFeature.implementation = function () {
            var myArray=new Array()
            myArray[0] = ""  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "startUsingNetworkFeature";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.startUsingNetworkFeature.apply(this, arguments);
        };
    }
});