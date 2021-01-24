/**
 * Created by maomao on 2020/3/6.
 */
Java.perform(function() {
   var cn = "android.location.Location";
   var location = Java.use(cn);
   if (location) {
       //hook getLatitude
       location.getLatitude.overload().implemention = function() {
           send("call " + location + "->getLatitude");
           return this.getLatitude.overload().apply(this, arguments);
       };
       //hook getLongitude
       location.getLongitude.overload().implemention = function() {
           send("call " + location + "->getLongitude");
           return this.getLongitude.overload().apply(this, arguments);
       };
   }
});