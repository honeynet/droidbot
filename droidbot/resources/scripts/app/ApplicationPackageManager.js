/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "android.app.ApplicationPackageManager";
    var appPackageManager = Java.use(cn);
    if (appPackageManager) {
        //hook setComponentEnableSetting
        appPackageManager.setComponentEnabledSetting.implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setComponentEnabledSetting";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setComponentEnabledSetting.apply(this, arguments);
        };
        //hook installPackage
        appPackageManager.installPackage.overloads[0].implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "installPackage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.installPackage.overloads[0].apply(this, arguments);
        };
        appPackageManager.installPackage.overloads[1].implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "installPackage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.installPackage.overloads[1].apply(this, arguments);
        };
        //hook getInstalledPackages
        appPackageManager.getInstalledPackages.overloads[0].implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getInstalledPackages";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getInstalledPackages.overloads[0].apply(this, arguments);
        };
        appPackageManager.getInstalledPackages.overloads[1].implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getInstalledPackages";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getInstalledPackages.overloads[1].apply(this, arguments);
        };
        //hook getInstalledApplications
        appPackageManager.getInstalledApplications.implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getInstalledApplications";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getInstalledApplications.apply(this, arguments);
        };
        //hook deletePackage
        appPackageManager.deletePackage.implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "deletePackage";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.deletePackage.apply(this, arguments);
        };
    };
});
