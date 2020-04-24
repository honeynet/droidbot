/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "org.xmlpull.v1.XmlPullParser";
    var target = Java.use(cn);
    if (target) {
        target.nextText.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "nextText";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.nextText.apply(this, arguments);
        };
    }
});