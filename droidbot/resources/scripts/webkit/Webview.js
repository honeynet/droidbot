/**
 * Created by maomao on 2020/3/15.
 */
Java.perform(function() {
    var cn = "android.webkit.WebView";
    var target = Java.use(cn);
    if (target) {
        target.loadData.implementation = function () {
          var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "loadData";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
          return this.loadData.apply(this, arguments);
        };

        target.getVisibility.implementation = function () {
          var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "getVisibility";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
          return this.getVisibility.apply(this, arguments);
        };

        target.removeAllViews.implementation = function () {
          var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "removeAllViews";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
          return this.removeAllViews.apply(this, arguments);
        };

        target.removeJavascriptInterface.implementation = function () {
          var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "removeJavascriptInterface";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
          return this.removeJavascriptInterface.apply(this, arguments);
        };

        target.saveWebArchive.overloads[0].implementation = function () {
          var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "saveWebArchive";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
          return this.saveWebArchive.overloads[0].apply(this, arguments);
        };
        target.saveWebArchive.overloads[1].implementation = function () {
          var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "saveWebArchive";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
          return this.saveWebArchive.overloads[1].apply(this, arguments);
        };

        target.setDownloadListener.implementation = function () {
          var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setDownloadListener";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
          return this.setDownloadListener.apply(this, arguments);
        };

        target.setTag.overloads[0].implementation = function () {
          var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setTag";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
          return this.setTag.overloads[0].apply(this, arguments);
        };
        target.setTag.overloads[1].implementation = function () {
          var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setTag";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
          return this.setTag.overloads[1].apply(this, arguments);
        };

        target.setVerticalScrollbarOverlay.implementation = function () {
          var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "setVerticalScrollbarOverlay";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
          return this.setVerticalScrollbarOverlay.apply(this, arguments);
        };

        target.loadData.implementation = function () {
          var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn + "." + "";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
          return this.loadData.apply(this, arguments);
        };

    }
});