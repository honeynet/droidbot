Java.perform(function() {
    var cn = "java.io.File";
    var file = Java.use(cn);
    if (file) {
        file.delete.implementaion = function() {
            send("call " + cn + "->delete");
            return this.delete.apply(this, arguments);
        };
    }
});