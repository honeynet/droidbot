Java.perform(function() {
    var cn = "java.lang.Runtime";
    var runtime = Java.use(cn);
    if (runtime) {
        runtime.exec.overload("java.lang.String").implementation = function(cmd) {
            if (cmd.indexOf("su") > -1) {
                send("call " + cn + "->exec_su");
            } else {
                send("call " + cn + "->exec for " + cmd);
            }
            return this.exec.overload("java.lang.String").apply(this, arguments);
        };
    }
});
