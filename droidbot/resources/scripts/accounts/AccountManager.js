/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.accounts.AccountManager";
    var target = Java.use(cn);
    if (target) {
        target.addAccount.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "addAccount";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.addAccount.apply(this, arguments);
        };

        target.addOnAccountsUpdatedListener.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "addOnAccountsUpdatedListener";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.addOnAccountsUpdatedListener.apply(this, arguments);
        };

        target.blockingGetAuthToken.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "blockingGetAuthToken";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.blockingGetAuthToken.apply(this, arguments);
        };

        target.confirmCredentials.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "confirmCredentials";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.confirmCredentials.apply(this, arguments);
        };

        target.editProperties.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "editProperties";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.editProperties.apply(this, arguments);
        };

        target.getAccounts.implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "getAccounts";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getAccounts.apply(this, arguments);
        };

        target.getAccountsByType.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "getAccountsByType";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getAccountsByType.apply(this, arguments);
        };

        target.getAccountsByTypeAndFeatures.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "getAccountsByTypeAndFeatures";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getAccountsByTypeAndFeatures.apply(this, arguments);
        };

        target.getAuthToken.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "getAuthToken";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getAuthToken.overloads[0].apply(this, arguments);
        };
        target.getAuthToken.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "getAuthToken";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getAuthToken.overloads[1].apply(this, arguments);
        };

        target.hasFeatures.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "hasFeatures";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.hasFeatures.apply(this, arguments);
        };

        target.removeAccount.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "removeAccount";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.removeAccount.overloads[0].apply(this, arguments);
        };
        target.removeAccount.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "removeAccount";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.removeAccount.overloads[1].apply(this, arguments);
        };

        target.updateCredentials.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = ""  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "updateCredentials";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.updateCredentials.apply(this, arguments);
        };
    }
});