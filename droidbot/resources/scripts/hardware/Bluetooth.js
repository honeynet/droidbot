/**
 * Created by maomao on 2020/4/12.
 */
Java.perform(function(){
    var cn = "android.hardware.Camera"
    var camera = Java.use(cn)
    if (camera) {
        camera.open.overloads[0].implementation = function(){
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "open";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.open.overloads[0].apply(this, arguments);
        };

        camera.open.overloads[1].implementation = function(){
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "open";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.open.overloads[1].apply(this, arguments);
        };
    }
});