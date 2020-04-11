/**
 * Created by maomao on 2020/3/6.
 */
Java.perform(function() {
    var cn = "android.location.LocationManager";
    var locationManager = Java.use(cn);
    if (locationManager) {
        //hook getProvider
        locationManager.getProvider.implementation = function() {
            send("call " + cn + "->getProvider");
            return this.getProvider.apply(this, arguments);
        };
        // //hook getCurrentLocation
        // locationManager.getCurrentLocation.implementation = function() {
        //     send("call " + cn + "->getCurrentLocation");
        //     return this.getCurrentLocation.apply(this, arguments);
        // };
        //hook getLastLocation
        locationManager.getLastKnownLocation.implementation = function() {
            send("call " + cn + "->getLastKnownLocation");
            return this.getLastKnownLocation.apply(this, arguments);
        };

    }
});