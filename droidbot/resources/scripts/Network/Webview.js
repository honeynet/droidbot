/**
 * Created by maomao on 2020/3/15.
 */
Java.perform(function() {
    var cn = "android.webkit.WebView";
    var view = Java.use(cn);
    if (view) {
        view.loadData.implementation = function () {
          send("call" + cn + "->implementation " + arguments);
          return this.loadData.apply(this, arguments);
        };

    }
});