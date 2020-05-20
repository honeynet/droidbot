/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "android.app.ActivityManager";
    var activityManager = Java.use(cn);
    if (activityManager) {
        //hook getRunningAppProcesses
        activityManager.getRunningAppProcesses.implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "getRunningAppProcesses";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getRunningAppProcesses.apply(this, arguments);
        };
        //hook forceStopPackage
        activityManager.forceStopPackage.implementation = function(packageName) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "forceStopPackage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.forceStopPackage.apply(this, arguments);
        };
        //hook restartPackage
        activityManager.restartPackage.implementation = function(packageName) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "restartPackage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.restartPackage.apply(this, arguments);
        }
        //hook killBackgroundProcesses
        activityManager.killBackgroundProcesses.implementation = function(packageName) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "killBackgroundProcesses";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.killBackgroundProcesses.apply(this, arguments);
        }
    }
});