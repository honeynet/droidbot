/**
 * Created by maomao on 2020/3/6.
 */
Java.perform(function() {
    var cn = "android.net.Uri";
    var uri = Java.use(cn);
    if (uri) {
        uri.parse.implementation = function(dest) {
            send("call " + cn + "->parse " + dest);
            return this.parse.apply(this, arguments);
        };
    }
});