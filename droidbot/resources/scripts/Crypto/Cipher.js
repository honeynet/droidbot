Java.perform(function() {
    var cn = "javax.crypto.Cipher";
    var cipher = Java.use(cn);
    if (cipher) {
        cipher.getInstance.overloads[0].implementation = function(transformation) {
            send("call " + cn + "->getInstance for " + transformation);
            return this.getInstance.overloads[0].apply(this, arguments);
        }
        cipher.getInstance.overloads[1].implementation = function(transformation) {
            send("call " + cn + "->getInstance for " + transformation);
            return this.getInstance.overloads[1].apply(this, arguments);
        }
        cipher.getInstance.overloads[2].implementation = function(transformation) {
            send("call " + cn + "->getInstance for " + transformation);
            return this.getInstance.overloads[2].apply(this, arguments);
        }
    }
});