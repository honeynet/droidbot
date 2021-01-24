Java.perform(function() {
    var httpclient = Java.use("org.apache.http.impl.client.DefaultHttpClient");
    if (httpclient) {
        // send("1");
        // //TODO: hook execute
        httpclient.execute.implementaion = function() {
            send("call " + "org.ap ache.http.impl.client.DefaultHttpClient" + "->execute");
            return this.execute.apply(this, arguments);
        };
    }
});