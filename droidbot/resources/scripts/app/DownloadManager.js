/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.app.DownloadManager";
    var target = Java.use(cn);
    if (target) {
        target.addCompletedDownload.overloads[0].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "addCompletedDownload";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.addCompletedDownload.overloads[0].apply(this, arguments);
        };
        target.addCompletedDownload.overloads[1].implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "addCompletedDownload";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.addCompletedDownload.overloads[1].apply(this, arguments);
        };

        target.enqueue.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "enqueue";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.enqueue.apply(this, arguments);
        };

        target.getUriForDownloadedFile.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "getUriForDownloadedFile";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getUriForDownloadedFile.apply(this, arguments);
        };
    }
});