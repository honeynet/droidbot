Java.perform(function() {
    var cn = "android.content.ContentResolver";
    var contentResolver = Java.use(cn);
    if (contentResolver) {
        //hook query
        contentResolver.query.overloads[0].implementation = function(uri) {
            if (uri.toString().indexOf("sms") > -1) {
                send("call " + cn + "->query_sms");
            }
            else if (uri.toString().indexOf("contacts") > -1) {
                send("call " + cn + "->query_contacts");
            }
            else if (uri.toString().indexOf("call") > -1) {
                send("call " + cn + "->query_call_log");
            } 
            else {
                send("call " + cn + "->query");
            }
            return this.query.overloads[0].apply(this, arguments);
        };
        //hook delete
        contentResolver.delete.implementation = function() {
            send("call " + cn + "->delete");
            return this.delete.apply(this, arguments);
        };
    }
});