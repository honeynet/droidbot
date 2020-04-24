/**
 * Created by maomao on 2020/3/6.
 */
Java.perform(function() {
   var cn = "android.location.Location";
   var location = Java.use(cn);
   if (location) {
       //hook getLatitude
       location.getLatitude.overload().implemention = function() {
           var myArray=new Array()
           myArray[0] = ""  //INTERESTED & SENSITIVE
           myArray[1] = cn + "." + "getLatitude";
           myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
           send(myArray);
           return this.getLatitude.overload().apply(this, arguments);
       };
       //hook getLongitude
       location.getLongitude.overload().implemention = function() {
           var myArray=new Array()
           myArray[0] = ""  //INTERESTED & SENSITIVE
           myArray[1] = cn + "." + "getLongitude";
           myArray[2] = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n\tat');
           send(myArray);
           return this.getLongitude.overload().apply(this, arguments);
       };
   }
});