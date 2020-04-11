Java.perform(function() {
    var cn = "java.net.URL";
    var url = Java.use(cn);
    if (url) {
        //hook openConnection
        url.openConnection.overloads[0].implementation = function () {
            send("call " + cn + "->openConnection");
            return this.openConnection.overloads[0].apply(this, arguments);
        };
        url.openConnection.overloads[1].implementation = function () {
            send("call " + cn + "->openConnection");
            return this.openConnection.overloads[1].apply(this, arguments);
        };
        //hook openStream
        url.openStream.implementation = function() {
            send("call " + cn + "->openStream");
            return this.openStream.apply(this, arguments);
        };
    }
});
