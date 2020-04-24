/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.widget.LinearLayout";
    var target = Java.use(cn);
    if (target) {
        target.setBackgroundDrawable.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setBackgroundDrawable";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setBackgroundDrawable.apply(this, arguments);
        };

        target.setMinimumWidth.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setMinimumWidth";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setMinimumWidth.apply(this, arguments);
        };
    }
});