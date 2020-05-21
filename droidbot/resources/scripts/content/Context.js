/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.content.Context";
    var target = Java.use(cn);
    if (target) {
        target.fileList.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "fileList";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.fileList.apply(this, arguments);
        };
    }
});