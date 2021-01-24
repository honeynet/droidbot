Java.perform(function() {
    var cn = "android.app.ApplicationPackageManager";
    var appPackageManager = Java.use(cn);
    if (appPackageManager) {
        //hook setComponentEnableSetting
        appPackageManager.setComponentEnabledSetting.implementation = function() {
            send("call " + cn + "->setComponentEnabledSetting");
            return this.setComponentEnabledSetting.apply(this, arguments);
        };
        //hook installPackage
        appPackageManager.installPackage.overloads[0].implementation = function() {
            send("call " + cn + "->installPackage");
            return this.installPackage.overloads[0].apply(this, arguments);
        };
        appPackageManager.installPackage.overloads[1].implementation = function() {
            send("call " + cn + "->installPackage");
            return this.installPackage.overloads[1].apply(this, arguments);
        };
        //hook getInstalledPackages
        appPackageManager.getInstalledPackages.overloads[0].implementation = function() {
            send("call " + cn + "->getInstalledPackages");
            return this.getInstalledPackages.overloads[0].apply(this, arguments);
        };
        appPackageManager.getInstalledPackages.overloads[1].implementation = function() {
            send("call " + cn + "->getInstalledPackages");
            return this.getInstalledPackages.overloads[1].apply(this, arguments);
        };
        //hook getInstalledApplications
        appPackageManager.getInstalledApplications.implementation = function() {
            send("call " + cn + "->getInstalledApplications");
            return this.getInstalledApplications.apply(this, arguments);
        };
        //hook deletePackage
        appPackageManager.deletePackage.implementation = function() {
            send("call " + cn + "->deletePackage");
            return this.deletePackage.apply(this, arguments);
        };
    };
});
