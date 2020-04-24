/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.telephony.gsm.GsmCellLocation";
    var target = Java.use(cn);
    if (target) {
        target.getCid.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getCid";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getCid.apply(this, arguments);
        };

        target.getLac.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getLac";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getLac.apply(this, arguments);
        };
    }
});