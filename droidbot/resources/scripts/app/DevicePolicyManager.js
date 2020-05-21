Java.perform(function() {
    var cn = "android.app.admin.DevicePolicyManager"
    var device = Java.use(cn);
    if (device) {
        //hook isAdminActive
        device.isAdminActive.implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "isAdminActive";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.isAdminActive.apply(this, arguments);
        };
        //hook resetPassword
        device.resetPassword.implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "resetPassword";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.resetPassword.apply(this, arguments);
        };
        //hook lockNow
        device.lockNow.implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "lockNow";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.lockNow.apply(this, arguments);
        };
    }
});