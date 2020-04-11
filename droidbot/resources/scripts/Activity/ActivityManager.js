Java.perform(function() {
    var cn = "android.app.ActivityManager";
    var activityManager = Java.use(cn);
    if (activityManager) {
        //hook getRunningAppProcesses
        activityManager.getRunningAppProcesses.implementation = function() {
            send("call " + cn + "->getRunningAppProcesses");
            return this.getRunningAppProcesses.apply(this, arguments);
        };
        //hook forceStopPackage
        activityManager.forceStopPackage.implementation = function(packageName) {
            send("call " + cn + "->forceStopPackage for " + packageName);
            return this.forceStopPackage.apply(this, arguments);
        };
        //hook restartPackage
        activityManager.restartPackage.implementation = function(packageName) {
            send("call " + cn + "->restartPackage for " + packageName);
            return this.restartPackage.apply(this, arguments);
        }
        //hook killBackgroundProcesses
        activityManager.killBackgroundProcesses.implementation = function(packageName) {
            send("call " + cn + "->killBackgroundProcesses for " + packageName);
            return this.killBackgroundProcesses.apply(this, arguments);
        }
    }
});