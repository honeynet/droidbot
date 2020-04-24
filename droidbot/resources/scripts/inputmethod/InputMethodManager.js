/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.view.inputmethod.InputMethodManager";
    var target = Java.use(cn);
    if (target) {
        target.showInputMethodAndSubtypeEnabler.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "showInputMethodAndSubtypeEnabler";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.showInputMethodAndSubtypeEnabler.apply(this, arguments);
        };
    }
});