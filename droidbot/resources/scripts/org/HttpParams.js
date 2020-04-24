/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "org.apache.http.params.HttpParams";
    var target = Java.use(cn);
    if (target) {
        target.setIntParameter.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setIntParameter";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setIntParameter.apply(this, arguments);
        };
    }
});