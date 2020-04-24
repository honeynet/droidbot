/**
 * Created by maomao on 2020/4/13.
 */
Java.perform(function () {
    var cn = "android.content.pm.PackageManager"
    var component = Java.use(cn)
    if(component) {
        component.setComponentEnabledSetting.implementation = function () {
            var myArray=new Array()
            myArray[0] = "SENSITIVE"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "setComponentEnabledSetting";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.setComponentEnabledSetting.apply(this, arguments);
        };
        component.getPackageArchiveInfo.implementation = function () {
            var myArray=new Array()
            myArray[0] = "INTERESTED"  //INTERESTED & SENSITIVE
            myArray[1] = cn +"." + "getPackageArchiveInfo";
            myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
            send(myArray);
            return this.getPackageArchiveInfo.apply(this, arguments);
        };
    }
});