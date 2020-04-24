/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.telephony.SubscriptionManager";
    var target = Java.use(cn);
    if (target) {
        target.addOnSubscriptionsChangedListener.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "addOnSubscriptionsChangedListener";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.addOnSubscriptionsChangedListener.overloads[0].apply(this, arguments);
        };
        // target.addOnSubscriptionsChangedListener.overloads[1].implementation = function(dest) {
        //     var myArray=new Array()
        //     myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
        //     myArray[1] = cn + "." + "addOnSubscriptionsChangedListener";
        //     myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
        //     send(myArray);
        //     return this.addOnSubscriptionsChangedListener.overloads[1].apply(this, arguments);
        // };

        target.getActiveSubscriptionInfo.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getActiveSubscriptionInfo";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getActiveSubscriptionInfo.overloads[0].apply(this, arguments);
        };
        // target.getActiveSubscriptionInfo.overloads[1].implementation = function(dest) {
        //     var myArray=new Array()
        //     myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
        //     myArray[1] = cn + "." + "getActiveSubscriptionInfo";
        //     myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
        //     send(myArray);
        //     return this.getActiveSubscriptionInfo.overloads[1].apply(this, arguments);
        // };

        target.getActiveSubscriptionInfoCount.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getActiveSubscriptionInfoCount";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getActiveSubscriptionInfoCount.apply(this, arguments);
        };

        target.getActiveSubscriptionInfoForSimSlotIndex.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getActiveSubscriptionInfoForSimSlotIndex";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getActiveSubscriptionInfoForSimSlotIndex.apply(this, arguments);
        };

        target.getActiveSubscriptionInfoList.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getActiveSubscriptionInfoList";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getActiveSubscriptionInfoList.apply(this, arguments);
        };
    }
});