/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.widget.CheckBox";
    var target = Java.use(cn);
    if (target) {
        target.getTextColors.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getTextColors";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getTextColors.overloads[0].apply(this, arguments);
        };
        target.getTextColors.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getTextColors";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getTextColors.overloads[1].apply(this, arguments);
        };
    }
});