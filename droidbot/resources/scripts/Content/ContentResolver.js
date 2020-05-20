/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "android.content.ContentResolver";
    var contentResolver = Java.use(cn);
    if (contentResolver) {
        //hook query
        contentResolver.query.overloads[0].implementation = function(uri) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "query";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            // if (uri.toString().indexOf("sms") > -1) {
            //     send("call " + cn + "->query_sms");
            // }
            // else if (uri.toString().indexOf("contacts") > -1) {
            //     send("call " + cn + "->query_contacts");
            // }
            // else if (uri.toString().indexOf("call") > -1) {
            //     send("call " + cn + "->query_call_log");
            // }
            // else {
            //     send("call " + cn + "->query");
            // }
            return this.query.overloads[0].apply(this, arguments);
        };
        //hook delete
        contentResolver.delete.implementation = function() {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "delete";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.delete.apply(this, arguments);
        };
    }
});