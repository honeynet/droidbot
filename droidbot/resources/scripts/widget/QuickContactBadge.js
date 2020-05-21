/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.widget.QuickContactBadge";
    var target = Java.use(cn);
    if (target) {
        target.assignContactFromEmail.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "assignContactFromEmail";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.assignContactFromEmail.overloads[0].apply(this, arguments);
        };
        target.assignContactFromEmail.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "assignContactFromEmail";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.assignContactFromEmail.overloads[1].apply(this, arguments);
        };

        target.assignContactFromPhone.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "assignContactFromPhone";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.assignContactFromPhone.overloads[0].apply(this, arguments);
        };
        target.assignContactFromPhone.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "assignContactFromPhone";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.assignContactFromPhone.overloads[0].apply(this, arguments);
        };

        target.onClick.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "onClick";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.onClick.apply(this, arguments);
        };
    }
});