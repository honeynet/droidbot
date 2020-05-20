/**
 * Created by maomao on 2020/4/24.
 */
Java.perform(function() {
    var cn = "java.security.MessageDigest";
    var messageDigest = Java.use(cn);
    if (messageDigest) {
        messageDigest.getInstance.overloads[0].implementation = function(algorithm) {
            send("call " + cn + "->getInstance for " + algorithm);
            return this.getInstance.overloads[0].apply(this, arguments);
        };
        messageDigest.getInstance.overloads[1].implementation = function(algorithm) {
            send("call " + cn + "->getInstance for " + algorithm);
            return this.getInstance.overloads[1].apply(this, arguments);
        };
        messageDigest.getInstance.overloads[2].implementation = function(algorithm) {
            send("call " + cn + "->getInstance for " + algorithm);
            return this.getInstance.overloads[2].apply(this, arguments);
        };
    }
});