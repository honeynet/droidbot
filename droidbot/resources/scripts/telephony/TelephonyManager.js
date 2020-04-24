/**
 * Created by maomao on 2020/3/6.
 */
Java.perform(function() {
    var cn = "android.telephony.TelephonyManager";
    var telephonyManager = Java.use(cn);
    if (telephonyManager) {
        //hook getSubscriberId
        telephonyManager.getSubscriberId.overload().implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getSubscriberId";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getSubscriberId.overload().apply(this, arguments);
        };
        //hook getDeviceId
        telephonyManager.getDeviceId.overload().implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getDeviceId";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getDeviceId.overload().apply(this, arguments);
        };
        //hook getLine1Number
        // telephonyManager.getLine1Number.implementation = function() {
        //     send("call " + cn + "->getLine1Number");
        //     return this.getLine1Number.apply(this, arguments);
        // };

        telephonyManager.getCellLocation.implementation = function() {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getCellLocation";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getCellLocation.overload().apply(this, arguments);
        };

        telephonyManager.listen.implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "listen";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.listen.overload().apply(this, arguments);
        }

        telephonyManager.getAllCellInfo.implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getAllCellInfo";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getAllCellInfo.overload().apply(this, arguments);
        }

        telephonyManager.getDeviceSoftwareVersion.overloads[0].implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getDeviceSoftwareVersion";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getDeviceSoftwareVersion.overloads[0].apply(this, arguments);
        }
        telephonyManager.getDeviceSoftwareVersion.overloads[1].implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getDeviceSoftwareVersion";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getDeviceSoftwareVersion.overloads[1].apply(this, arguments);
        }

        telephonyManager.getGroupIdLevel1.overloads[0].implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getGroupIdLevel1";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getGroupIdLevel1.overloads[0].apply(this, arguments);
        }
        telephonyManager.getGroupIdLevel1.overloads[1].implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getGroupIdLevel1";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getGroupIdLevel1.overloads[1].apply(this, arguments);
        }

        telephonyManager.getNeighboringCellInfo.implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getNeighboringCellInfo";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getNeighboringCellInfo.overload().apply(this, arguments);
        }

        telephonyManager.getSimSerialNumber.overloads[0].implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getSimSerialNumber";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getSimSerialNumber.overloads[0].apply(this, arguments);
        }
        telephonyManager.getSimSerialNumber.overloads[1].implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getSimSerialNumber";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getSimSerialNumber.overloads[1].apply(this, arguments);
        }

        telephonyManager.getVoiceMailAlphaTag.overloads[0].implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getVoiceMailAlphaTag";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getVoiceMailAlphaTag.overloads[0].apply(this, arguments);
        }
        telephonyManager.getVoiceMailAlphaTag.overloads[1].implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getVoiceMailAlphaTag";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getVoiceMailAlphaTag.overloads[1].apply(this, arguments);
        }

        telephonyManager.getVoiceMailNumber.overloads[0].implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getVoiceMailNumber";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getVoiceMailNumber.overloads[0].apply(this, arguments);
        }
        telephonyManager.getVoiceMailNumber.overloads[1].implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getVoiceMailNumber";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getVoiceMailNumber.overloads[1].apply(this, arguments);
        }
    }
});