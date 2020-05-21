/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.widget.RadioButton";
    var target = Java.use(cn);
    if (target) {
        target.isChecked.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "isChecked";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.isChecked.apply(this, arguments);
        };

        target.setOnCheckedChangeListener.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setOnCheckedChangeListener";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setOnCheckedChangeListener.apply(this, arguments);
        };
    }
});