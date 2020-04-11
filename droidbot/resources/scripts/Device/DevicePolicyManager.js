Java.perform(function() {
    var cn = "android.app.admin.DevicePolicyManager"
    var device = Java.use(cn);
    if (device) {
        //hook isAdminActive
        device.isAdminActive.implementation = function() {
            send("call " + cn + "->isAdminActive");
            return this.isAdminActive.apply(this, arguments);
        };
        //hook resetPassword
        device.resetPassword.implementation = function() {
            send("call " + cn + "->resetPassword");
            return this.resetPassword.apply(this, arguments);
        };
        //hook lockNow
        device.lockNow.implementation = function() {
            send("call " + cn + "->lockNow");
            return this.lockNow.apply(this, arguments);
        };
    }
});