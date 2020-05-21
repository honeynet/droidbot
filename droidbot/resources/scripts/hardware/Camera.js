/**
 * Created by maomao on 2020/4/12.
 */
Java.perform(function(){
    var cn = "android.bluetooth.BluetoothAdapter"
    var bluetooth = Java.use(cn)
    if (bluetooth) {
        bluetooth.getAddress.implementation = function(){
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "getAddress";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getAddress.apply(this, arguments);
        };
    }
});