/**
 * Created by maomao on 2020/4/20.
 */
Java.perform(function() {
    var cn = "android.provider.Browser";
    var target = Java.use(cn);
    if (target) {
        target.addSearchUrl.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "addSearchUrl";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.addSearchUrl.apply(this, arguments);
        };

        target.clearHistory.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "clearHistory";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.clearHistory.apply(this, arguments);
        };

        target.clearSearches.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "clearSearches";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.clearSearches.apply(this, arguments);
        };

        target.deleteFromHistory.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "deleteFromHistory";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.deleteFromHistory.apply(this, arguments);
        };

        target.deleteHistoryTimeFrame.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "deleteHistoryTimeFrame";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.deleteHistoryTimeFrame.apply(this, arguments);
        };

        target.truncateHistory.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "truncateHistory";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.truncateHistory.apply(this, arguments);
        };

        target.updateVisitedHistory.implementation = function(dest) {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "updateVisitedHistory";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.updateVisitedHistory.apply(this, arguments);
        };
    }
});